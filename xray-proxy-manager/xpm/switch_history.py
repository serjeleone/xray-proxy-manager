from __future__ import annotations

import threading
from pathlib import Path
from typing import Any

from . import common, persistence


WINDOW_SECONDS = 12 * 60 * 60
BUCKET_SECONDS = 5 * 60


class SwitchHistory:
    """Persist completed outbound changes independently of the rotating UI log.

    Equal-second events share a counter. Keeping second precision makes the
    oldest partial five-minute bucket exact, without an unbounded event list.
    The file is read once; chart requests use the in-memory counters.
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        self.lock = threading.RLock()
        self.events: dict[int, int] = {}
        self.write_failed = False
        now = common.now_ts()
        data = persistence.load_json(path, {})
        rows = data.get('events', []) if isinstance(data, dict) and data.get('version') == 1 else []
        if isinstance(rows, list):
            for row in rows:
                if (isinstance(row, list) and len(row) == 2
                        and type(row[0]) is int and type(row[1]) is int
                        and now - WINDOW_SECONDS < row[0] <= now and row[1] > 0):
                    self.events[row[0]] = self.events.get(row[0], 0) + row[1]

    def _prune(self, now: int) -> None:
        self.events = {ts: count for ts, count in self.events.items()
                       if now - WINDOW_SECONDS < ts <= now}

    def record(self, timestamp: int | None = None) -> None:
        now = common.now_ts() if timestamp is None else timestamp
        with self.lock:
            self._prune(now)
            self.events[now] = self.events.get(now, 0) + 1
            try:
                persistence.atomic_write_json(self.path, {
                    'version': 1,
                    'events': sorted([ts, count] for ts, count in self.events.items()),
                })
                self.write_failed = False
            except OSError as exc:
                # Statistics must never undo an already completed routing change.
                # Keep the counters in memory and retry on the next change.
                if not self.write_failed:
                    common.log(f'could not persist outbound switch history: {exc}', error=True)
                self.write_failed = True

    def payload(self, timestamp: int | None = None) -> dict[str, Any]:
        now = common.now_ts() if timestamp is None else timestamp
        start = now - WINDOW_SECONDS
        first = start // BUCKET_SECONDS * BUCKET_SECONDS
        last = now // BUCKET_SECONDS * BUCKET_SECONDS
        with self.lock:
            self._prune(now)
            counts: dict[int, int] = {}
            for ts, count in self.events.items():
                bucket = ts // BUCKET_SECONDS * BUCKET_SECONDS
                counts[bucket] = counts.get(bucket, 0) + count
            return {
                'start': start, 'end': now, 'bucket_seconds': BUCKET_SECONDS,
                'total': sum(counts.values()), 'persisted': not self.write_failed,
                'buckets': [
                    {'start': max(start, ts), 'end': min(now, ts + BUCKET_SECONDS),
                     'count': counts.get(ts, 0)}
                    for ts in range(first, last + 1, BUCKET_SECONDS)
                ],
            }


class SwitchHistoryMixin:
    def record_outbound_change(self, previous, current, timestamp: int | None = None) -> None:
        # Restarts, subscription config reloads and unsuccessful attempts are not
        # outbound changes. Count at the same commit points as the success log.
        if previous is None or current is None or self.same_candidate_identity(previous, current):
            return
        self.switch_history.record(timestamp)
