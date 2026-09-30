from __future__ import annotations

import re
import subprocess
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


def human_subscription_error(error: Any) -> str:
    """Keep curl diagnostics in logs and expose a short actionable explanation."""
    raw = str(error).strip()
    text = raw.lower()
    # Already translated application errors remain stable across status refreshes.
    if any('\u0400' <= char <= '\u04ff' for char in raw) and 'curl:' not in text:
        return raw
    codes = re.findall(r'curl: \((\d+)\)', text)
    code = int(codes[-1]) if codes else None
    if isinstance(error, (TimeoutError, subprocess.TimeoutExpired)) or code == 28 or any(
        marker in text for marker in ('timeout', 'timed out')
    ):
        return 'Превышен интервал ожидания соединения с сервером подписки. Повторите обновление позже.'
    if code == 22 or 'requested url returned' in text:
        statuses = re.findall(r'(?:returned error:|http(?: error)?[: ]+)\s*(\d{3})', text)
        status = int(statuses[-1]) if statuses else None
        if status in (401, 403):
            return 'Сервер отклонил доступ к подписке. Проверьте ссылку и срок действия подписки.'
        if status in (404, 410):
            return 'Подписка не найдена на сервере. Проверьте ссылку на подписку.'
        if status == 429:
            return 'Слишком много запросов к серверу подписки. Повторите обновление позже.'
        return 'Сервер подписки вернул ошибку. Повторите обновление позже.'
    messages = (
        ((5, 6), ('could not resolve',), 'Не удалось определить адрес сервера подписки. Проверьте интернет-соединение и DNS.'),
        ((60, 51, 58, 77), ('certificate',), 'Не удалось проверить сертификат сервера подписки. Проверьте дату и время устройства или обратитесь к провайдеру подписки.'),
        ((35,), ('ssl', 'tls'), 'Не удалось установить защищённое соединение с сервером подписки. Повторите обновление позже.'),
        ((67,), ('authentication', 'auth failed'), 'Не удалось пройти авторизацию на прокси. Проверьте настройки доступа к прокси.'),
        ((7,), ('connection refused', 'failed to connect'), 'Не удалось подключиться к серверу подписки. Проверьте интернет-соединение и повторите обновление.'),
        ((97,), ('socks5',), 'Не удалось загрузить подписку через прокси. Проверьте доступность выбранного outbound.'),
        ((52,), ('empty reply',), 'Сервер подписки не прислал ответ. Повторите обновление позже.'),
        ((18, 55, 56), ('connection reset', 'recv failure', 'partial file'), 'Соединение с сервером подписки было прервано. Повторите обновление.'),
        ((1, 3), ('url rejected', 'malformed'), 'Некорректная ссылка на подписку. Проверьте адрес в настройках.'),
        ((47,), ('redirect',), 'Сервер подписки перенаправляет запрос слишком много раз. Проверьте ссылку на подписку.'),
        ((), ('json', 'utf-8', 'codec', 'expecting value', 'expecting property name', 'extra data', 'unterminated string'), 'Сервер вернул подписку в неподдерживаемом формате. Проверьте ссылку: ожидается конфигурация Xray в формате JSON.'),
    )
    for curl_codes, markers, message in messages:
        if code in curl_codes or any(marker in text for marker in markers):
            return message
    return 'Не удалось обновить подписку. Повторите попытку позже; подробности доступны в логах.'
