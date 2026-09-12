from __future__ import annotations

from typing import Any


class ProbeFailure(RuntimeError):
    """The candidate itself failed validation, as opposed to selector/control errors."""


class SwitchCancelled(RuntimeError):
    """A newer manual choice or changed policy cancelled an automatic operation."""


def human_probe_error(error: Any) -> str:
    text = str(error).lower()
    messages = (
        (('timeout', 'timed out', 'curl: (28)', 'тайм-аут'), 'Превышен тайм-аут проверки'),
        (('latency threshold', 'порог задержки'), 'Превышен допустимый порог задержки'),
        (('could not resolve', 'curl: (5)', 'curl: (6)', 'dns'), 'Не удалось определить адрес сервера'),
        (('certificate', 'curl: (60)'), 'Ошибка сертификата сервера'),
        (('ssl', 'tls', 'curl: (35)'), 'Не удалось установить защищённое соединение'),
        (('authentication', 'auth failed', 'curl: (67)', 'user was rejected'), 'Ошибка авторизации прокси'),
        (('connection refused', 'failed to connect', 'curl: (7)'), 'Не удалось подключиться к серверу'),
        (('curl: (22)', 'http error', 'requested url returned'), 'Проверочный адрес вернул ошибку HTTP'),
        (('curl: (97)', 'socks5'), 'Прокси отклонил соединение'),
        (('curl: (52)', 'empty reply'), 'Сервер не ответил'),
        (('curl: (56)', 'connection reset', 'recv failure'), 'Соединение прервано сервером'),
        (('decode config', 'config validation', 'invalid config', 'dependencies'), 'Некорректная конфигурация outbound'),
        (('did not open', 'not running', 'stopped'), 'Не удалось запустить Xray для проверки'),
    )
    for markers, message in messages:
        if message.lower() in text or any(marker in text for marker in markers):
            return message
    return 'Outbound не прошёл проверку доступности'
