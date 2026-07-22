# Xray Proxy Manager

[![Validate](https://github.com/serjeleone/xray-proxy-manager/actions/workflows/validate.yml/badge.svg)](https://github.com/serjeleone/xray-proxy-manager/actions/workflows/validate.yml)
[![Build](https://github.com/serjeleone/xray-proxy-manager/actions/workflows/build.yml/badge.svg)](https://github.com/serjeleone/xray-proxy-manager/actions/workflows/build.yml)
[![Добавить репозиторий в Home Assistant](https://my.home-assistant.io/badges/supervisor_add_addon_repository.svg)](https://my.home-assistant.io/redirect/supervisor_add_addon_repository/?repository_url=https%3A%2F%2Fgithub.com%2Fserjeleone%2Fxray-proxy-manager)

Xray Proxy Manager — приложение Home Assistant для управления Xray с использованием JSON-subscription, проверки доступных outbound и бесшовного переключения между двумя независимыми SOCKS5-слотами для отказоустойчивости.

Приложение подготавливает новый outbound в резервном слоте, проверяет его, переводит внешний selector на этот слот и сохраняет предыдущий процесс до завершения отслеживаемых соединений. Способ подключения клиентов и передачи соединений в слоты определяется внешней инфраструктурой и не входит в состав проекта.

**Автор и сопровождающий:** [serjeleone](https://github.com/serjeleone)

## Возможности

- загрузка и периодическое обновление JSON-подписки;
- отображение outbound, протокола, адреса и результата проверки;
- ручное и автоматическое тестирование;
- автоматический выбор доступного outbound с меньшей задержкой;
- два Xray-процесса: `xray-a` и `xray-b`;
- предварительный запуск и проверка резервного слота;
- переключение совместимого selector через HTTP API;
- сохранение старого слота до завершения отслеживаемых соединений;
- автоматический откат при ошибках сразу после переключения;
- восстановление последней рабочей конфигурации;
- веб-интерфейс через Home Assistant Ingress;
- встроенный просмотр журнала приложения и изменений текущего релиза;
- сборка контейнеров для `amd64` и `aarch64` через GitHub Actions.

## Сетевые интерфейсы

| Порт | Назначение |
|---|---|
| `10808/tcp` | SOCKS5-слот `xray-a` |
| `10808/udp` | UDP relay SOCKS5-слота `xray-a` |
| `10809/tcp` | SOCKS5-слот `xray-b` |
| `10809/udp` | UDP relay SOCKS5-слота `xray-b` |

Порты можно изменить в настройках приложения. Они должны отличаться.

`socks_tcp_a` и `socks_tcp_b` задают номера SOCKS5-inbound соответствующих слотов. `socks_udp_a` и `socks_udp_b` являются независимыми флагами UDP relay; отдельные номера UDP-портов не задаются, поскольку каждый слот использует для TCP и UDP один и тот же номер порта.

## Установка

1. Откройте **Настройки → Приложения → Магазин приложений**.
2. Откройте меню репозиториев.
3. Добавьте:

   ```text
   https://github.com/serjeleone/xray-proxy-manager
   ```

4. Установите **Xray Proxy Manager**.
5. Укажите `subscription_url`.
6. При использовании двухслотового переключения настройте параметры `selector_*`.
7. Запустите приложение и откройте веб-интерфейс.

## Минимальная конфигурация

```yaml
subscription_url: "https://example.com/subscription.json"
listen_lan: true
socks_tcp_a: 10808
socks_tcp_b: 10809
socks_udp_a: true
socks_udp_b: true
selector_control_enabled: true
selector_api_url: "http://192.0.2.1:9090"
selector_api_secret: ""
selector_tag: "xray-active"
```

`192.0.2.1` — документационный пример. Укажите адрес совместимого selector API, доступный из контейнера приложения.

Selector должен содержать элементы с точными именами:

```text
xray-a
xray-b
```

API должно поддерживать:

- чтение текущего элемента selector;
- выбор элемента selector;
- получение списка соединений с цепочкой используемых outbound.

Без `selector_control_enabled` приложение запускает текущий слот, выполняет проверки и обслуживает интерфейс, но двухслотовое переключение недоступно.

## Сборка

Workflow `.github/workflows/build.yml` публикует образ:

```text
ghcr.io/serjeleone/xray-proxy-manager
```

Поддерживаемые платформы:

```text
linux/amd64
linux/arm64
```

Версия приложения и тег образа определяются полем `version` в `xray-proxy-manager/config.yaml`.

## Документация

Полное описание параметров и алгоритма работы находится в [`xray-proxy-manager/DOCS.md`](xray-proxy-manager/DOCS.md).
