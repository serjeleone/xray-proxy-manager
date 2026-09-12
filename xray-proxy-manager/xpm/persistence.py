from __future__ import annotations

import copy
import json
import os
import shutil
import tempfile
from pathlib import Path
from typing import Any
from . import common as xpm_common, models as xpm_models


def atomic_write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    # Independent writers must never share one .tmp file. mkstemp also keeps
    # subscription credentials and saved runtime configuration private.
    with tempfile.NamedTemporaryFile(
        mode='w', encoding='utf-8', dir=path.parent,
        prefix=f'.{path.name}.', delete=False,
    ) as file_handle:
        temp_path = Path(file_handle.name)
        try:
            json.dump(payload, file_handle, ensure_ascii=False, indent=2, sort_keys=True)
            file_handle.write('\n')
            file_handle.flush()
            os.replace(temp_path, path)
        finally:
            temp_path.unlink(missing_ok=True)


def load_json(path: Path, default: Any) -> Any:
    try:
        with path.open('r', encoding='utf-8') as file_handle:
            return json.load(file_handle)
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return copy.deepcopy(default)


def migrate_legacy_workdir() -> None:
    if not xpm_common.LEGACY_WORKDIR.exists() or xpm_common.LEGACY_WORKDIR == xpm_common.WORKDIR:
        return
    xpm_common.WORKDIR.mkdir(parents=True, exist_ok=True)
    for source in list(xpm_common.LEGACY_WORKDIR.iterdir()):
        target = xpm_common.WORKDIR / source.name
        if target.exists():
            continue
        shutil.move(str(source), str(target))
    try:
        xpm_common.LEGACY_WORKDIR.rmdir()
    except OSError:
        pass


class PersistenceMixin:
    def save_state(self) -> None:
        self.state['active_candidate_id'] = self.active_candidate_id
        self.state['active_slot_tag'] = self.active_slot_tag
        atomic_write_json(xpm_common.STATE_PATH, self.state)

    def save_latencies(self) -> None:
        for candidate in self.candidates:
            result = self.latencies.get(candidate.id)
            if result is not None and candidate.config_revision:
                result.setdefault('config_revision', candidate.config_revision)
        atomic_write_json(xpm_common.LATENCY_PATH, self.latencies)

    def invalidate_candidate_probe(self, candidate_id: str) -> None:
        if not hasattr(self, 'latency_versions'):
            self.latency_versions = {}
        self.latency_versions[candidate_id] = self.latency_versions.get(candidate_id, 0) + 1

    def resolve_last_good_candidate(self) -> xpm_models.Candidate | None:
        metadata = load_json(xpm_common.LAST_GOOD_META_PATH, {})
        if isinstance(metadata, dict):
            fingerprint = str(metadata.get('fingerprint') or '')
            if fingerprint:
                match = next((item for item in self.candidates if item.fingerprint == fingerprint), None)
                if match:
                    return match
            candidate_id = str(metadata.get('candidate_id') or '')
            if candidate_id:
                match = self.candidate_by_id(candidate_id)
                if match:
                    return match
            outbound_tag = str(metadata.get('outbound_tag') or '')
            source_index = metadata.get('source_index')
            if outbound_tag:
                match = self.candidate_by_tag(
                    outbound_tag,
                    int(source_index) if isinstance(source_index, int) else None,
                )
                if match:
                    return match

        config = load_json(xpm_common.LAST_GOOD_CONFIG_PATH, {})
        if isinstance(config, dict):
            routing = config.get('routing') if isinstance(config.get('routing'), dict) else {}
            rules = routing.get('rules') if isinstance(routing.get('rules'), list) else []
            if rules and isinstance(rules[0], dict):
                outbound_tag = str(rules[0].get('outboundTag') or '')
                if outbound_tag:
                    return self.candidate_by_tag(outbound_tag)
        return None

    def restore_last_good(self) -> tuple[bool, xpm_models.Candidate | None]:
        if not xpm_common.LAST_GOOD_CONFIG_PATH.exists():
            return False, None
        metadata = load_json(xpm_common.LAST_GOOD_META_PATH, {})
        saved_slot = (
            str(metadata.get('slot_tag') or self.active_slot_tag)
            if isinstance(metadata, dict) else self.active_slot_tag
        )
        if not self.dual_slot_enabled:
            saved_slot = 'xray-a'
        elif saved_slot not in xpm_common.SLOT_TAGS:
            saved_slot = 'xray-a'

        config = load_json(xpm_common.LAST_GOOD_CONFIG_PATH, {})
        if not isinstance(config, dict) or not config:
            xpm_common.log('last good config is empty or malformed', error=True)
            return False, None
        # A 0.4.x last-good file still exposes HTTP directly on 10809. Always
        # rewrite managed inbounds for the selected slot before validating it,
        # so emergency recovery also works after the blue-green port migration.
        config = self.patch_inbounds(config, slot_tag=saved_slot)
        self.apply_socks_access_rules(config)
        temp_path = self.slots[saved_slot].config_path.with_name(
            f'{self.slots[saved_slot].config_path.stem}.restore.json'
        )
        atomic_write_json(temp_path, config)
        ok, output = self.xray_test(temp_path)
        if not ok:
            temp_path.unlink(missing_ok=True)
            xpm_common.log(f'last good config is invalid after slot migration: {output}', error=True)
            return False, None

        self.active_slot_tag = saved_slot
        os.replace(temp_path, self.slots[saved_slot].config_path)
        shutil.copy2(self.slots[saved_slot].config_path, xpm_common.CONFIG_PATH)
        shutil.copy2(self.slots[saved_slot].config_path, xpm_common.LAST_GOOD_CONFIG_PATH)
        if not isinstance(metadata, dict):
            metadata = {}
        metadata['slot_tag'] = saved_slot
        metadata['migrated_at'] = xpm_common.now_ts()
        atomic_write_json(xpm_common.LAST_GOOD_META_PATH, metadata)

        candidate = self.resolve_last_good_candidate()
        if candidate:
            self.slots[saved_slot].candidate_id = candidate.id
            self.slots[saved_slot].candidate_name = candidate.name
            self.slots[saved_slot].candidate = candidate
        return True, candidate
