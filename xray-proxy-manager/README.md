# Xray Proxy Manager

[![Validate](https://github.com/serjeleone/xray-proxy-manager/actions/workflows/validate.yml/badge.svg)](https://github.com/serjeleone/xray-proxy-manager/actions/workflows/validate.yml)
[![Build](https://github.com/serjeleone/xray-proxy-manager/actions/workflows/build.yml/badge.svg)](https://github.com/serjeleone/xray-proxy-manager/actions/workflows/build.yml)
[![Добавить репозиторий в Home Assistant](https://my.home-assistant.io/badges/supervisor_add_addon_repository.svg)](https://my.home-assistant.io/redirect/supervisor_add_addon_repository/?repository_url=https%3A%2F%2Fgithub.com%2Fserjeleone%2Fxray-proxy-manager)

Xray Proxy Manager — приложение Home Assistant для загрузки Xray JSON-subscription, проверки outbound и переключения между двумя независимыми SOCKS5-слотами.

Новая конфигурация предварительно запускается в свободном слоте и проходит проверку до изменения активного пути. После переключения предыдущий Xray-процесс продолжает обслуживать уже принятые соединения, пока они не завершатся естественно или пока не будет выполнена принудительная остановка. Способ передачи соединений в слоты определяется внешней системой.

## Возможности

- загрузка и периодическое обновление JSON-подписки;
- отображение outbound, протокола, адреса и результата проверки;
- закрепление активного outbound в начале списка и дренируемого сразу под ним;
- ручное и автоматическое тестирование;
- автоматический выбор доступного outbound с меньшей задержкой;
- при запуске учитываются сохранённые успешные измерения: запомненный outbound не восстанавливается, если допустимый вариант быстрее не менее чем на настроенный порог;
- два независимых Xray-процесса: `xray-a` и `xray-b`;
- предварительный запуск и проверка резервного слота;
- переключение совместимого selector через HTTP API;
- запрет одновременного использования одного outbound в двух слотах;
- контроль дренирования старого слота и настраиваемый предельный срок ожидания;
- ручная принудительная остановка дренируемого слота;
- автоматический откат при ошибках сразу после переключения;
- восстановление последней рабочей конфигурации;
- опциональное управление правилом firewall (для дополнительной маршрутизации) на роутере OpenWrt через SSH;
- веб-интерфейс через Home Assistant Ingress;
- просмотр, поиск, копирование и выгрузка журналов;
- просмотр изменений текущего релиза по нажатию на версию;
- multi-arch сборка для `amd64` и `aarch64` через GitHub Actions.

## Сетевые интерфейсы

| Порт | Назначение |
|---|---|
| `10808/tcp` | SOCKS5-слот `xray-a` |
| `10808/udp` | UDP relay SOCKS5-слота `xray-a` |
| `10809/tcp` | SOCKS5-слот `xray-b` |
| `10809/udp` | UDP relay SOCKS5-слота `xray-b` |

`socks_tcp_a` и `socks_tcp_b` задают номера SOCKS5-inbound. Флаги `socks_udp_a` и `socks_udp_b` независимо включают UDP relay в соответствующем слоте. TCP и UDP одного слота используют один номер порта.

## Установка

1. Откройте **Настройки → Приложения → Магазин приложений**.
2. Добавьте репозиторий:

   ```text
   https://github.com/serjeleone/xray-proxy-manager
   ```

3. Установите **Xray Proxy Manager**.
4. Укажите `subscription_url`.
5. Для двухслотового переключения настройте параметры `selector_*`.
6. Запустите приложение и откройте веб-интерфейс.

## Минимальная конфигурация

```yaml
subscription_url: "https://example.com/subscription.json"
listen_lan: true
socks_tcp_a: 10808
socks_tcp_b: 10809
socks_udp_a: true
socks_udp_b: true
selector_control_enabled: true
selector_api_url: "http://192.168.0.1:9090"
selector_api_secret: ""
selector_tag: "xray-active"
drain_timeout_minutes: 0
auto_switch_excluded_countries: "RU, Лучший сервер"
```

Selector должен содержать элементы с точными именами `xray-a` и `xray-b`. Значение `drain_timeout_minutes: 0` сохраняет неограниченное ожидание естественного завершения соединений.

В `auto_switch_excluded_countries` можно совместить точные двухбуквенные коды стран и текстовые фрагменты. Например, `RU, GAMING, Лучший сервер` исключает страну `RU` и любой outbound, в имени или технических полях которого встречаются  фрагменты `GAMING` или `Лучший сервер`.

## Опциональное управление правилом firewall на OpenWrt

Кнопка play/pause в верхнем блоке может включать и отключать указанное правило firewall на совместимом узле OpenWrt через SSH. Функция не участвует в механике Xray-слотов и может быть отключена параметром `router_control_enabled`. Может быть использована в дополнительных правилах маршрутизации трафика.

Для подключения поддерживаются существующий ключ, указанный путь к ключу, автоматически создаваемый ключ и пароль. Требуемые параметры перечислены в [`DOCS.md`](xray-proxy-manager/DOCS.md).

## Документация

Полное описание архитектуры, настроек и алгоритма работы находится в [`xray-proxy-manager/DOCS.md`](xray-proxy-manager/DOCS.md).

## Версия

Текущая версия приложения: `0.6.3`.

