# Общие блоки конфигурации (shared)

Справочник по интерфейсу sing-box **1.14.2**. Здесь описаны блоки полей, которые встраиваются во многие объекты конфига: поля подключения (dial), поля прослушивания (listen), UDP NAT, TLS клиента и сервера, провайдеры сертификатов и DNS-01, V2Ray-транспорты, мультиплексирование, TCP Brutal, UDP over TCP, параметры HTTP/2 и QUIC, а также кратко поиск соседей и состояние Wi-Fi. HTTP-клиент и pre-match здесь только упомянуты: их основное описание — в [config.md](config.md#http_clients) и [route.md](route.md#pre-match).

Смежные файлы: протоколы — [outbounds.md](outbounds.md) и [inbounds.md](inbounds.md); DNS-серверы и правила — [dns.md](dns.md); маршрутизация, `rule_set`, `default_domain_resolver`, `default_http_client` — [route.md](route.md); верхний уровень конфига (списки `http_clients` с полями HTTP-клиента, `certificate_providers`, `network_namespaces`, раздел `certificate`) и правила разбора JSON — [config.md](config.md); команды `check`, `format`, `generate` — [cli.md](cli.md); сводка устаревшего — [deprecations.md](deprecations.md); `experimental` — [experimental.md](experimental.md).

## Условные обозначения

- Типы записаны как типы JSON: `string`, `int`, `bool`, `object`, `[object]`.
- `string|[string]` — поле типа `badoption.Listable`: можно указать одно значение без скобок или массив.
- `duration` — строка в синтаксисе длительностей Go (`"300ms"`, `"1.5h"`, `"2h45m"`); суффикс дней тоже принимается (проверено: `"1d"`). Число вместо строки — ошибка разбора (`cannot unmarshal number ... of type string`). Исключение — `udp_timeout` в listen-полях, см. ниже.
- `size` — объём памяти: целое число байт или строка «число + единица» (`"64 MB"`, `"8MB"`, `"8M"`, `"8 kB"`, `"1GB"`, `"8 B"`, `"8 TB"`); регистр единицы не важен, пробел необязателен. Основание — **1024**: `k`/`kb` = КиБ, `m`/`mb` = МиБ, `g`/`gb` = ГиБ и далее до `e`/`eb` (тип `byteformats.MemoryBytes` библиотеки sing, таблица `memoryUnitValueTable`; сверено с исходником библиотеки той версии, что в go.mod 1.14.2). Отвергаются: `KiB`/`MiB` (в этой таблице их нет), дробные значения (`"1.5 MB"`), строка без единицы (`"8"`). Так разбираются окна приёма HTTP/2 и QUIC, `stream_receive_window`/`quic_session_receive_window` у naive, `memory_limit` у `experimental.debug` и `memory_limit`/`safety_margin` у сервиса `oom-killer`. Скорости `up`/`down` у hysteria v1 — другой тип (сетевые единицы, основание 1000), см. [outbounds.md](outbounds.md#hysteria).
- `mark` — `int` или строка с числом в любой записи Go (`"0x1234"`, `"4660"`).
- `-> outbound`, `-> inbound`, `-> dns server`, `-> http_client`, `-> certificate_provider`, `-> network_namespace` — ссылка по тегу.
- «с 1.X» — поле появилось в версии 1.X (отмечается для 1.10 и новее); поля без пометки старше 1.10.
- «check» — `sing-box check`: разбор JSON плюс `box.New` (создание всех объектов, чтение файлов сертификатов), но без `Start`. «При старте» — ошибка в `Start`, check её не видит. «При подключении» — ленивая проверка при первом использовании: ни check, ни старт её не видят.
- Имена ключей сопоставляются без учёта регистра: проверено, что `"Detour"` в dial-полях и `"DOMAIN_RESOLVER": {"SERVER": …}` понимаются как `detour` и `domain_resolver.server`. Полное правило (включая неизвестные поля) — в [config.md](config.md).

Исходники: option/types.go, option/tun.go (`FwMark`), cmd/sing-box/cmd_check.go.

## Поля подключения (dial)

Набор полей, общий для всех объектов, которые сами открывают исходящие соединения: исходящие direct, socks, http, shadowsocks, vmess, trojan, vless, naive, hysteria, hysteria2, tuic, shadowtls, anytls, snell, ssh, tor; эндпоинты wireguard, openvpn, openconnect, tailscale; удалённые DNS-серверы ([dns.md](dns.md)), NTP, хэндшейк Reality-сервера и HTTP-клиент. Поля вкладываются в объект-владелец плоско, без отдельного ключа.

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `detour` | string -> outbound | — | Открывать соединение через другой исходящий (цепочка). Прочие поля сокета тогда не действуют, подробности ниже. У `direct` запрещено: check — `` `detour` is not supported in direct context``. |
| `bind_interface` | string | — | Привязать сокет к сетевому интерфейсу по имени. Только Linux, macOS, Windows (на прочих — ошибка при создании). На Windows это имя адаптера (`Ethernet`, `Wi-Fi`); существование интерфейса check не проверяет — ошибка при подключении. |
| `inet4_bind_address` | string (IPv4) | — | Локальный адрес для IPv4-соединений. Только IP-литерал, имя хоста — ошибка разбора. |
| `inet6_bind_address` | string (IPv6) | — | То же для IPv6. |
| `bind_address_no_port` | bool | `false` | с 1.13. Только Linux: не резервировать порт при привязке к адресу (`IP_BIND_ADDRESS_NO_PORT`), порт выбирается при `connect`, что позволяет переиспользовать его при уникальной четвёрке адресов. На Windows check: `` `bind_address_no_port` is only supported on Linux``. |
| `protect_path` | string | — | В документации отсутствует (есть в коде и в schema.json). Путь unix-сокета, которому передаётся дескриптор каждого сокета, чтобы внешний процесс «защитил» его от собственного туннеля. Для Windows-сценария смысла не имеет. |
| `routing_mark` | mark | `0` | Только Linux: метка netfilter (`SO_MARK`). Ненулевое значение на Windows — check: `` `routing_mark` is only supported on Linux``. При включённом `tun.auto_redirect` — ошибка при подключении (конфликт). |
| `reuse_addr` | bool | `false` | `SO_REUSEADDR`. По коду применяется только к UDP-сокетам, которые исходящий открывает под датаграммы, а не к TCP-соединению. |
| `netns` | string -> network_namespace | — | с 1.12; ссылка на тег из `network_namespaces` — с 1.14. Только Linux: имя сетевого пространства, абсолютный путь или тег. На Windows check проходит, ошибка — при подключении. Ссылаться на пространство типа `unshare` не рекомендуется: его единственный выход наружу — tun самого sing-box. |
| `connect_timeout` | duration | `5s` | Тайм-аут установки соединения. Умолчание в документации не указано, в коде — `C.TCPConnectTimeout`. |
| `tcp_fast_open` | bool | `false` | TCP Fast Open. Заодно выключает параллельный перебор адресов после резолва (адреса пробуются по очереди). Конфликтует с `network_strategy`. |
| `tcp_multi_path` | bool | `false` | Multipath TCP. В Go MPTCP есть только на Linux; на Windows поле ни на что не влияет. По коду флаг выставляется только IPv4-дайлеру. |
| `disable_tcp_keep_alive` | bool | `false` | с 1.13. Выключить TCP keep-alive. |
| `tcp_keep_alive` | duration | `5m` | с 1.13. Простой до первой keep-alive пробы. |
| `tcp_keep_alive_interval` | duration | `75s` | с 1.13. Интервал между пробами. |
| `udp_fragment` | bool | `false`; у direct, hysteria, hysteria2, tuic — `true` | Разрешить фрагментацию исходящих UDP-датаграмм. При `false` сокету ставится запрет фрагментации (DF). |
| `domain_resolver` | string \| object -> dns server | см. ниже | с 1.12. Каким DNS-сервером и с какими параметрами резолвить доменное имя. |
| `network_strategy` | string | `default` | с 1.11. `default`, `hybrid`, `fallback`. Действует только в графических клиентах Android и Apple при включённом `route.auto_detect_interface`; в CLI на Windows принимается и ни на что не влияет. Неизвестное значение — ошибка разбора. |
| `network_type` | string\|[string] | сеть по умолчанию | с 1.11. `wifi`, `cellular`, `ethernet`, `other`. Та же оговорка по платформам. |
| `fallback_network_type` | string\|[string] | все прочие сети | с 1.11. Запасные типы сети для стратегии `fallback`. Та же оговорка. |
| `fallback_delay` | duration | `300ms` | Сколько ждать перед запасной попыткой: между IPv4 и IPv6 (RFC 6555) при параллельном наборе адресов после резолва и между интерфейсами при `network_strategy`. |
| `domain_strategy` | string | — | Устарело в 1.12; в 1.14.2 по умолчанию приводит к фатальной ошибке, см. ниже. |

### detour: что действует вместе с ним

- С `detour` sing-box не создаёт собственный сокет, поэтому `bind_interface`, адреса привязки, `routing_mark`, `reuse_addr`, `netns`, `connect_timeout`, TFO, MPTCP, keep-alive, `udp_fragment` и сетевые стратегии не применяются.
- Исключение по коду: `domain_resolver` с непустым `server`. Тогда доменный адрес сервера резолвится локально указанным DNS-сервером, и в `detour` уходит уже IP-адрес (адреса пробуются по очереди). Без `domain_resolver` доменное имя передаётся в `detour` как есть, и его разрешает тот исходящий, через который идёт соединение. `domain_strategy` вместе с `detour` (без `domain_resolver.server`) молча игнорируется.
- Несуществующий тег в `detour` или кольцо из detour'ов: check проходит, `Start` падает (`dependency[X] not found for outbound[Y]`, `circular outbound dependency`) — подробности в [outbounds.md](outbounds.md).
- `detour` на «пустой» `direct` (direct без единого dial-поля): для исходящих ошибка `detour to an empty direct outbound makes no sense` возникает только при первом соединении; для DNS-серверов — при старте. check не видит ни того, ни другого.

### domain_resolver

Задаёт, как разрешать доменное имя. Строка — сокращение для объекта с одним `server`.

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `server` | string -> dns server | — (обязательно) | Тег DNS-сервера. Пустой `server` в объектной форме — ошибка разбора `empty domain_resolver.server`. Несуществующий тег — check: `domain resolver not found: X`, но только когда адрес действительно доменный. |
| `strategy` | string | `""` | `prefer_ipv4`, `prefer_ipv6`, `ipv4_only`, `ipv6_only`; `""` или `as_is` — без ограничений. `prefer_ipv6` меняет, какое семейство адресов пробуется первым при параллельном наборе. |
| `timeout` | duration | `dns.timeout` | с 1.14. Тайм-аут этого запроса. |
| `disable_cache` | bool | `false` | Не читать и не пополнять DNS-кэш этим запросом. |
| `disable_optimistic_cache` | bool | `false` | с 1.14. Не использовать оптимистичный кэш для этого запроса. |
| `rewrite_ttl` | int (uint32) \| null | `null` | Переписать TTL в ответе. |
| `client_subnet` | string (IP или префикс) \| null | `null` | Добавить EDNS0 Client Subnet; адрес без маски дополняется до `/32` или `/128`. |

Какое имя разрешается:

| Владелец | Разрешаемое имя |
|---|---|
| исходящий `direct` | доменное имя назначения из запроса |
| прочие исходящие и эндпоинты | доменное имя в `server` |
| DNS-серверы | доменное имя в адресе DNS-сервера ([dns.md](dns.md)) |

Когда поле нужно (порядок проверок в `NewWithOptions` / `NewDNSQueryOptions`):

1. Адрес — IP-литерал: поле не используется, даже несуществующий тег не проверяется. Задан `detour`, а `domain_resolver` нет: имя уходит в `detour` как есть, и ни одно из требований ниже не действует (проверено для исходящего и для DNS-сервера).
2. Задан `domain_resolver`: берётся указанный сервер (несуществующий тег — ошибка check).
3. Владелец — DNS-сервер: `domain_resolver` обязателен, иначе жёсткая ошибка `missing domain resolver for domain server address` без обходного флага. Ни `route.default_domain_resolver`, ни число DNS-серверов здесь не учитываются (проверено: ошибка и при одном сервере, и при заданном `default_domain_resolver`).
4. Иначе действует `route.default_domain_resolver` ([route.md](route.md)), если он задан; несуществующий тег — ошибка check `default domain resolver not found`, даже когда DNS-сервер всего один (проверено).
5. Иначе, если DNS-серверов меньше двух, берётся сервер по умолчанию.
6. Иначе у исходящего `naive`, клиентов `openvpn`/`openconnect`, эндпоинта `tailscale` и службы `derp` — та же жёсткая ошибка `missing domain resolver for domain server address`, а у остальных владельцев срабатывает устаревшая «неявная» логика, в 1.14.2 фатальная: check завершается с `missing route.default_domain_resolver or domain_resolver in dial fields is deprecated … set environment variable ENABLE_DEPRECATED_MISSING_DOMAIN_RESOLVER=true` (проверено).

Расхождение с документацией: документация говорит, что объект имеет формат действия `route` DNS-правил без `action`. В коде у `domain_resolver` только семь полей из таблицы выше, а неизвестные ключи внутри объекта молча игнорируются (объект разбирается без запрета неизвестных полей). Например, `speculative`, `remove_client_subnet` или опечатка проходят check с кодом 0 и ни на что не влияют.

### domain_strategy (устаревшее)

Значения `prefer_ipv4`, `prefer_ipv6`, `ipv4_only`, `ipv6_only`. Устарело в 1.12, удаление было запланировано на 1.14. В 1.14.2 поле всё ещё разбирается:

- если адрес доменный, `detour` не задан (или задан `domain_resolver.server`), а `domain_resolver.strategy` пуст — check и запуск завершаются фатально: `legacy domain strategy options is deprecated … set environment variable ENABLE_DEPRECATED_LEGACY_DOMAIN_STRATEGY_OPTIONS=true`. С этой переменной окружения, равной `true`, выводится предупреждение, и значение работает как `domain_resolver.strategy` (проверено);
- для IP-адреса сервера или вместе с `detour` поле молча игнорируется (check 0);
- если задан и `domain_resolver.strategy`, побеждает он, предупреждения нет.

Замена: `"domain_resolver": {"server": "<тег>", "strategy": "…"}`. В deprecated.md этого пункта нет, есть только в migration.md.

### Сетевые стратегии

Семантика (только графические клиенты Android и Apple): `default` — сеть по умолчанию либо сети из `network_type` по очереди; `hybrid` — все сети (или перечисленные) одновременно; `fallback` — предпочтительные сети, а при их отказе или тайм-ауте запасные; после отказа клиент на 15 секунд переходит в режим «быстрого отката» (все сети сразу) и выходит из него, как только предпочтительная сеть восстановилась.

Конфликт проверяется на любой платформе, включая Windows. Если задан `bind_interface`, `inet4_bind_address`, `inet6_bind_address` или `tcp_fast_open` и при этом задан `network_strategy` (либо `network_type` без `fallback_network_type` и без `fallback_delay`), check завершается ошибкой `` `network_strategy` is conflict with `bind_interface`, `inet4_bind_address`, `inet6_bind_address` and `tcp_fast_open` ``. Документация не упоминает `tcp_fast_open`.

### Dial-поля на Windows

| Поле | Поведение в 1.14.2 на Windows |
|---|---|
| `bind_interface`, `inet4/6_bind_address`, `reuse_addr`, `connect_timeout`, `tcp_fast_open`, keep-alive, `udp_fragment`, `domain_resolver` | работают |
| `routing_mark` (ненулевой), `bind_address_no_port` | check: ошибка «only supported on Linux» |
| `netns` | check проходит, ошибка при подключении |
| `tcp_multi_path`, `network_strategy`, `network_type`, `fallback_network_type` | принимаются, не действуют |
| `protect_path` | принимается; механизм рассчитан на unix-сокеты Android/Linux |

Исходники: option/outbound.go (`DialerOptions`, `DomainResolveOptions`), option/types.go, common/dialer/dialer.go (`NewWithOptions`, `NewDNSQueryOptions`), dns/transport_dialer.go, common/dialer/default.go, common/dialer/detour.go, common/dialer/resolve.go, common/listener/listener.go (`ListenNetworkNamespace`), constant/timeout.go, constant/network.go, protocol/direct/outbound.go, adapter/outbound/adapter.go, experimental/deprecated/constants.go, experimental/deprecated/stderr.go; документация: docs/configuration/shared/dial.md, docs/migration.md.

## Поля прослушивания (listen)

Набор полей для всех объектов со своим слушающим сокетом: входящие socks, http, mixed, direct, shadowsocks, vmess, trojan, vless, naive, hysteria, hysteria2, tuic, shadowtls, anytls, snell, redirect, tproxy; эндпоинт openvpn-server; сервисы api, ssm-api, resolved, derp, ccm, ocm, usbip-server, hysteria-realm. У `tun` и `cloudflared` этих полей нет: `listen` у `tun` — ошибка `unknown field "listen"` (проверено), хотя документация tun ссылается на listen-поля; `udp_timeout` и `netns` у `tun` — собственные поля ([inbounds.md](inbounds.md#поля-tun)). Поля вкладываются в объект плоско. Этот раздел — основное описание listen-полей; передача соединений между входящими через `detour` разобрана в [inbounds.md](inbounds.md#detour-и-инъекция-соединений).

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `listen` | string (IP) | `127.0.0.1` | Адрес прослушивания. Только IP-литерал: имя хоста (`"localhost"`) или адрес с портом (`"0.0.0.0:80"`) — ошибка разбора `ParseAddr` (проверено). `0.0.0.0` или `::` — все интерфейсы. Документация помечает поле обязательным, но код без него слушает `127.0.0.1`. |
| `listen_port` | int (0–65535) | `0` | Порт; `0` — порт выбирает ОС. Больше 65535 — ошибка разбора (проверено). |
| `bind_interface` | string | — | с 1.12. Привязать слушающий сокет к интерфейсу по имени. На Windows — через `IP_UNICAST_IF`/`IPV6_UNICAST_IF`. |
| `routing_mark` | mark | `0` | с 1.12. Метка netfilter (`SO_MARK`), только Linux. На других ОС молча игнорируется: функция установки метки там пустая (`control.RoutingMark` в библиотеке sing, mark_other.go). check проходит, ошибки при открытии сокета нет. В dial-полях, наоборот, ненулевое значение вне Linux — ошибка check. |
| `reuse_addr` | bool | `false` | с 1.12. На Linux — `SO_REUSEADDR` и `SO_REUSEPORT`; на Windows — `SO_REUSEADDR` (в семантике Windows это разрешает занять уже занятый порт). |
| `netns` | string -> network_namespace | — | с 1.12; тег из `network_namespaces` — с 1.14. Сетевое пространство имён (имя, путь или тег), только Linux. На Windows check проходит, по коду — ошибка при старте (`get netns …`). |
| `tcp_fast_open` | bool | `false` | TCP Fast Open на слушателе. На Windows слушатель с TFO поддерживается библиотекой tfo-go (вывод по тегам сборки, не проверено). |
| `tcp_multi_path` | bool | `false` | MPTCP на слушателе; Go включает его только на Linux, на прочих ОС поле молча не действует. |
| `disable_tcp_keep_alive` | bool | `false` | с 1.13. Выключить TCP keep-alive на принятых соединениях. |
| `tcp_keep_alive` | duration | `5m` | с 1.13. Время простоя до первой пробы keep-alive (в 1.13 умолчание изменено с `10m` на `5m`). |
| `tcp_keep_alive_interval` | duration | `75s` | с 1.13 (по changelog; документация пометки не ставит). Интервал между пробами. |
| `udp_fragment` | bool | `false`; у входящих direct, hysteria, hysteria2, tuic — `true` | Разрешить фрагментацию UDP. При `false` на сокете ставится запрет фрагментации (на Windows — `IP_DONTFRAGMENT`). |
| `udp_timeout` | duration \| int | `5m` | Время жизни UDP-сессии (записи NAT) без трафика. Целое число — секунды (совместимость со старым форматом); строка без единицы (`"5"`) — ошибка разбора. Действует у direct, mixed, socks, shadowsocks, hysteria, hysteria2, tuic, tproxy; у прочих типов поле принимается, но UDP-сессиями они так не управляют. |
| `detour` | string -> inbound | — | Передавать принятые соединения в другой входящий, который поддерживает инъекцию ([inbounds.md](inbounds.md#detour-и-инъекция-соединений)). Тег не проверяется ни check, ни стартом: при каждом соединении — `inbound detour not found`. Указание на самого себя — `routing loop on detour`. |

Удалённые поля:

| Поле | Состояние в 1.14.2 |
|---|---|
| `sniff`, `sniff_override_destination`, `sniff_timeout`, `domain_strategy`, `udp_disable_domain_unmapping` | Устарели в 1.11, удалены в 1.13. Любое непустое значение — ошибка разбора `legacy inbound fields are deprecated in sing-box 1.11.0 and removed in sing-box 1.13.0, checkout migration: …` (проверено). У `tun` те же поля — ошибка создания (`initialize inbound[0]: legacy inbound fields …`). Замена — действия правил `sniff` и `resolve`, опция `udp_disable_domain_unmapping` в `route`/`route-options` ([route.md](route.md#действия-правил), [deprecations.md](deprecations.md#listen-поля-входящих-listenoptions-см-sharedmd)). |
| `proxy_protocol`, `proxy_protocol_accept_no_header` | Удалены в 1.6. Разбор и check проходят (проверено), ошибка `Proxy Protocol is deprecated and removed in sing-box 1.6.0` — при открытии TCP-слушателя, то есть при старте. |

Исходники: option/inbound.go (`ListenOptions`, `InboundOptions`, `UDPTimeoutCompat`), common/listener/listener.go, common/listener/listener_tcp.go, common/listener/listener_udp.go, route/route.go (inbound detour); библиотека sing: common/control (`RoutingMark` — mark_linux.go и mark_other.go, `ReuseAddr`, `DisableUDPFragment`, bind_windows.go); документация: docs/configuration/shared/listen.md.

## UDP NAT

Поля поведения UDP NAT у tun и tproxy, эндпоинта wireguard, клиента и сервера openvpn, клиента openconnect. `udp_timeout` у tproxy и сервера openvpn приходит из listen-полей, у остальных — собственное поле объекта (у tailscale тоже есть свой `udp_timeout`).

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `udp_timeout` | duration; у tun, tproxy, openvpn и tailscale также int в секундах, у wireguard и openconnect — только duration | `5m` | Время жизни записи NAT без трафика. |
| `udp_mapping` | string | `endpoint_independent` | с 1.14. Когда заводится новое отображение: `endpoint_independent` — одно на локальный источник для всех адресатов; `address_dependent` — отдельное для каждого адреса назначения; `address_and_port_dependent` — для каждой пары адрес+порт. |
| `udp_filtering` | string | `endpoint_independent` | с 1.14. Какие входящие пакеты пропускаются: `endpoint_independent` — от любого узла; `address_dependent` — только с адресов, куда уже отправляли; `address_and_port_dependent` — только с пар адрес+порт, куда уже отправляли. |
| `udp_nat_max` | int (uint32) | `0` (авто) | с 1.14. Предел числа UDP-сессий; при достижении закрывается самая давно использованная. `0`: на iOS 4096, на прочих платформах от 4096 до 16384 в зависимости от объёма памяти (16384, если объём не определён). |

Неизвестное значение `udp_mapping`/`udp_filtering` — ошибка разбора (`unknown UDP NAT behavior`). Входящий tproxy существует только на Linux; на Windows check его пропускает.

Исходники: option/inbound.go (`UDPNATBehavior`), option/tun.go, option/redir.go, option/wireguard.go, option/openvpn.go, option/openconnect.go, protocol/redirect/tproxy.go, protocol/tun/inbound.go; документация: docs/configuration/shared/udp-nat.md.

## TLS

Объект `tls` в исходящих и входящих, которые допускают TLS (список по протоколам — в [outbounds.md](outbounds.md) и [inbounds.md](inbounds.md)), у DNS-серверов `tls`, `https`, `quic`, `h3` ([dns.md](dns.md)) и у HTTP-клиента. Клиентская и серверная формы различаются.

Общие правила:

- При `"enabled": false` весь блок игнорируется, даже с недопустимыми значениями внутри (проверено: check 0).
- Почти все ошибки блока возникают при создании объекта, поэтому check их ловит. Это касается и файлов: `certificate_path`, `key_path` и подобные читаются при создании, отсутствующий файл — ошибка check. Относительные пути отсчитываются от рабочего каталога sing-box (`-D`).
- На сервере `certificate_path`, `key_path`, `client_certificate_path` и ECH `key_path` перечитываются при изменении файла.
- Значения версий TLS: `1.0`, `1.1`, `1.2`, `1.3`; другое — ошибка при создании (`unknown tls version`).
- `cipher_suites` — имена из `crypto/tls` Go, например `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`, `TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256`, `TLS_RSA_WITH_AES_128_GCM_SHA256`. Порядок не важен, настраиваются только наборы для TLS 1.0–1.2. Имена наборов TLS 1.3 (`TLS_AES_128_GCM_SHA256` и др.) принимаются без ошибки, но ничего не меняют; неизвестное имя — ошибка `unknown cipher_suite`.
- `curve_preferences` (с 1.13): `P256`, `P384`, `P521`, `X25519`, `X25519MLKEM768` (регистр не важен); порядок не важен. Пусто — набор Go по умолчанию.

### Исходящий TLS (клиент)

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `enabled` | bool | `false` | Включить TLS. |
| `engine` | string | `go` | с 1.14. Реализация TLS: `go`, `windows` (Schannel), `apple`. Подробности ниже. Неизвестное значение — `unknown tls engine`. |
| `disable_sni` | bool | `false` | Не отправлять SNI. Сертификат всё равно сверяется с `server_name` (если не `insecure`). Несовместимо с Reality и движками `windows`/`apple`. |
| `server_name` | string | адрес из `server` | Имя для SNI и для проверки сертификата. IP-адрес в SNI не отправляется, сертификат сверяется с IP. Если имени нет и не задан `insecure` — `missing server_name or insecure=true`. |
| `insecure` | bool | `false` | Принимать любой сертификат сервера. |
| `alpn` | string\|[string] | зависит от транспорта | Протоколы ALPN по убыванию предпочтения. Транспорты подставляют своё значение, если поле пустое (см. раздел V2Ray-транспортов). |
| `min_version` | string | `1.2` | Минимальная версия TLS. |
| `max_version` | string | `1.3` | Максимальная версия TLS. |
| `cipher_suites` | string\|[string] | набор Go | Наборы шифров TLS 1.0–1.2. |
| `curve_preferences` | string\|[string] | набор Go | с 1.13. При включённом uTLS молча игнорируется (отпечаток диктует свой набор). |
| `certificate` | string\|[string] | — | Доверенные сертификаты в PEM (строки массива склеиваются через `\n`). Заменяет набор корневых сертификатов целиком: системные корни и раздел `certificate` верхнего уровня ([config.md](config.md)) для этого соединения не используются. Невалидный PEM — ошибка создания. |
| `certificate_path` | string | — | То же из файла. |
| `certificate_public_key_sha256` | string\|[string] (base64) | — | с 1.13. Закрепление ключа: SHA-256 от SubjectPublicKeyInfo листового сертификата, в стандартном base64. Цепочка, срок и имя тогда не проверяются вовсе, сверяется только хэш; проверка хэша действует и при `insecure: true`. Нельзя вместе с `certificate`/`certificate_path` (ошибка при создании). |
| `client_certificate` | string\|[string] | — | с 1.13. Клиентский сертификат (PEM) для mTLS. |
| `client_certificate_path` | string | — | с 1.13. То же из файла. |
| `client_key` | string\|[string] | — | с 1.13. Закрытый ключ клиента (PEM). Без пары к сертификату — ошибка `client certificate and client key must be provided together`. |
| `client_key_path` | string | — | с 1.13. То же из файла. |
| `fragment` | bool | `false` | с 1.12. Резать ClientHello на TCP-сегменты против простых фильтров по открытому тексту. |
| `fragment_fallback_delay` | duration | `500ms` | с 1.12. Пауза между сегментами, если автоматически измерить задержку не удалось. |
| `record_fragment` | bool | `false` | с 1.12. Резать ClientHello на несколько TLS-записей (дешевле, чем `fragment`). |
| `spoof` | string | — | с 1.14. Перед настоящим ClientHello отправить поддельный с этим SNI. |
| `spoof_method` | string | `wrong-sequence` | с 1.14. Как сделать поддельный сегмент неприемлемым для сервера. |
| `kernel_tx` | bool | `false` | с 1.13. kTLS на отправку. Только Linux 5.1+ и TLS 1.3; на Windows check: `kTLS is only supported on Linux`. |
| `kernel_rx` | bool | `false` | с 1.13. kTLS на приём; те же ограничения, производительность только ухудшает. |
| `handshake_timeout` | duration | `15s` | с 1.14. Тайм-аут TLS-рукопожатия. |
| `ech` | object | — | Encrypted Client Hello, ниже. |
| `utls` | object | — | Подделка отпечатка ClientHello, ниже. |
| `reality` | object | — | Клиент Reality, ниже. |

#### Движки TLS (engine)

- `go` — стандартная реализация; все поля таблицы.
- `windows` — Schannel через SSPI, только Windows build 17763+ (Windows 10 1809, Server 2019). TLS 1.3 договаривается только на Windows 11 / Server 2022 и новее, на старых системах максимум 1.2. Поддерживаются `server_name`, `insecure`, `alpn`, `min_version`, `max_version`, `certificate`/`certificate_path`, `certificate_public_key_sha256`, `handshake_timeout`. Любое другое поле (`disable_sni`, `cipher_suites`, `curve_preferences`, клиентский сертификат, `fragment`/`record_fragment`, `spoof`, kTLS, `ech`, `utls`, `reality`) — ошибка при создании, например `utls is unsupported in Windows TLS engine` (проверено).
- `apple` — Network.framework, только на платформах Apple; на Windows check: `Apple TLS engine is not available on non-Apple platforms`.

#### uTLS (utls)

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `enabled` | bool | `false` | Строить ClientHello по образцу браузера (библиотека uTLS). |
| `fingerprint` | string | `chrome` | Отпечаток, ниже. Неизвестное имя — `unknown uTLS fingerprint` при создании. |

Значения `fingerprint` по коду: `chrome` (и пустая строка), `firefox`, `edge`, `safari`, `360`, `qq`, `ios`, `android` (OkHttp Android 11), `random` (один из chrome/firefox/edge/safari/ios, выбирается один раз при запуске процесса), `randomized` (случайно сгенерированный ClientHello с TLS 1.3 и без P-256 в первом key share). Старые имена `chrome_psk`, `chrome_psk_shuffle`, `chrome_padding_psk_shuffle`, `chrome_pq`, `chrome_pq_psk` с 1.10 принимаются как синоним `chrome`.

Сами авторы sing-box не рекомендуют uTLS для обхода блокировок: отпечаток лишь копирует формат рукопожатия и распознаваем; против анализа отпечатков они советуют NaiveProxy.

#### ECH клиента (ech)

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `enabled` | bool | `false` | Шифровать ClientHello (ECH). |
| `config` | string\|[string] | — | Конфигурация ECH в PEM (блок `ECH CONFIGS`); иной PEM — `invalid ECH configs pem`. |
| `config_path` | string | — | То же из файла. |
| `query_server_name` | string | `server_name` | с 1.13. Какое имя запрашивать в DNS (запись HTTPS), если конфигурация не задана. |
| `pq_signature_schemes_enabled` | bool | — | Устарело в 1.12, удалено в 1.13: значение `true` — ошибка при создании; `false` молча принимается. |
| `dynamic_record_sizing_disabled` | bool | — | То же. |

Если `config` и `config_path` пусты, конфигурация ECH берётся из DNS при подключении. Пару ключ/конфигурация создаёт `sing-box generate ech-keypair <имя>` ([cli.md](cli.md)). ECH несовместим с Reality.

#### Reality клиента (reality)

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `enabled` | bool | `false` | Режим Reality. |
| `public_key` | string | — (обязательно) | Открытый ключ сервера: base64url без выравнивания, ровно 32 байта; иначе `invalid public_key` / `decode public_key`. Пару создаёт `sing-box generate reality-keypair`. |
| `short_id` | string | `""` | Hex-строка до 16 символов (до 8 байт). Нечётная длина — ошибка `decode short_id`. Длиннее 16 символов — sing-box не выдаёт ошибку, а падает с `panic: index out of range` (check завершается кодом 2; проверено). Пусто — нулевой идентификатор. |

Требования по коду: нужен `utls.enabled: true`, иначе при создании `uTLS is required by reality client` (документация этого прямо не говорит); несовместимо с `ech` (`Reality is conflict with ECH`), `disable_sni` и `spoof`. `server_name` — домен маскировки, который увидит сторонний наблюдатель.

#### Фрагментация и spoof

- `fragment` рассчитан на примитивные фильтры по открытому тексту и медленный; сначала стоит пробовать `record_fragment` и включать это только для заведомо блокируемых имён. Паузу между сегментами sing-box измеряет сам на Linux, Apple и Windows (на Windows нужны права администратора); иначе ждёт `fragment_fallback_delay`. Если измеренная задержка меньше 20 мс (цель локальная или за прозрачным прокси), тоже используется фиксированная пауза.
- `spoof` посылает перед настоящим ClientHello его копию, отличающуюся только SNI. Промежуточный фильтр видит «разрешённое» имя, а сервер отбрасывает подделку по способу из `spoof_method`:

| `spoof_method` | Чем подделка неприемлема для сервера |
|---|---|
| `wrong-sequence` (умолчание) | номер последовательности TCP до окна приёма сервера |
| `wrong-checksum` | неверная контрольная сумма TCP |
| `wrong-ack` | номер подтверждения до окна отправки сервера |
| `wrong-md5` | опция подписи TCP-MD5, которую сервер не ждёт |
| `wrong-timestamp` | устаревшая метка времени TCP (отказ по PAWS); не работает на macOS |

- Проверки `spoof` при создании (ловит check): нужно SNI (не `disable_sni`, `server_name` не пуст и не IP) — иначе `` `spoof` requires TLS ClientHello with SNI``; `spoof` не должен совпадать с `server_name`; `spoof_method` без `spoof` — ошибка; с Reality и с движками `windows`/`apple` — ошибка.
- Платформы: Linux (нужны `CAP_NET_RAW` и `CAP_NET_ADMIN`), macOS (root), Windows amd64 и 386 (администратор; при первом использовании устанавливается встроенный драйвер WinDivert). Windows ARM64 не поддерживается. На Windows check с `spoof` проходит; права и драйвер нужны при подключении.

### Входящий TLS (сервер)

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `enabled` | bool | `false` | Включить TLS. |
| `server_name` | string | — | Для Reality — единственное допустимое SNI клиента. |
| `insecure` | bool | `false` | В документации отсутствует. Если нет ни сертификата, ни ключа, сервер выпускает самоподписанный сертификат на лету под SNI каждого клиента. Вместе с `certificate_provider` или `acme` — ошибка `tls: insecure unused`. |
| `alpn` | string\|[string] | — | Предлагаемые протоколы ALPN (ACME добавляет свои после них). |
| `min_version` | string | `1.2` | |
| `max_version` | string | `1.3` | |
| `cipher_suites` | string\|[string] | набор Go | |
| `curve_preferences` | string\|[string] | набор Go | с 1.13. С Reality — ошибка `curve preferences is unavailable in reality`. |
| `certificate` | string\|[string] | — | Цепочка сертификатов сервера (PEM). |
| `certificate_path` | string | — | То же из файла; перечитывается при изменении. |
| `key` | string\|[string] | — | Закрытый ключ (PEM). |
| `key_path` | string | — | То же из файла; перечитывается при изменении. |
| `client_authentication` | string | `no` | с 1.13. `no`, `request`, `require-any`, `verify-if-given`, `require-and-verify`; иное — ошибка разбора. |
| `client_certificate` | string\|[string] | — | с 1.13. Доверенные сертификаты для проверки клиентов (PEM). |
| `client_certificate_path` | string\|[string] | — | с 1.13. Файлы с ними; перечитываются при изменении. |
| `client_certificate_public_key_sha256` | string\|[string] (base64) | — | с 1.13. Хэши открытых ключей допустимых клиентов. |
| `kernel_tx` | bool | `false` | с 1.13. kTLS; только Linux. |
| `kernel_rx` | bool | `false` | с 1.13. kTLS; только Linux. |
| `handshake_timeout` | duration | `15s` | с 1.14. |
| `certificate_provider` | string -> certificate_provider \| object | — | с 1.14. Сертификаты от провайдера (тег или встроенный объект), см. ниже. Вместе с `acme` — ошибка `certificate_provider and acme are mutually exclusive`. Несуществующий тег check пропускает. |
| `acme` | object | — | Устарело в 1.14, удаление в 1.16. Встроенный ACME, ниже. |
| `ech` | object | — | ECH сервера, ниже. |
| `reality` | object | — | Сервер Reality, ниже. |

Без `certificate_provider`, `acme` (с непустым `domain`) и `insecure` сертификат и ключ обязательны: `missing certificate` / `missing key` при создании.

#### Проверка клиентских сертификатов

- Если задан `client_certificate` или `client_certificate_path`, а `client_authentication` не задан или `no`, режим автоматически становится `require-and-verify`.
- В режимах `verify-if-given` и `require-and-verify` источник доверия выбирается по порядку: `client_certificate`, затем `client_certificate_path`, затем `client_certificate_public_key_sha256` (тогда режим ослабляется до `request`/`require-any`, а проверяется только хэш ключа). Если нет ни одного — ошибка `missing client_certificate, client_certificate_path or client_certificate_public_key_sha256 for client authentication`.
- Хэши ключей без явного `client_authentication` не действуют: режим остаётся `no`.
- `request` и `require-any` сертификат запрашивают (или требуют), но не проверяют.

#### ECH сервера (ech)

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `enabled` | bool | `false` | Принимать ECH. |
| `key` | string\|[string] | — | Ключи ECH (PEM). |
| `key_path` | string | — | То же из файла; перечитывается при изменении. |
| `pq_signature_schemes_enabled` | bool | — | Удалено в 1.13: `true` — ошибка, `false` принимается. |
| `dynamic_record_sizing_disabled` | bool | — | То же. |

При `enabled` без ключей — `missing ECH keys`. С Reality несовместимо.

#### Reality сервера (reality)

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `enabled` | bool | `false` | Режим Reality. |
| `handshake` | object | — | Настоящий сайт для маскировки: `server` (string), `server_port` (int) плюс все [dial-поля](#поля-подключения-dial). Документация помечает обязательным; без него check проходит, адрес получается пустым, и сервер не сможет проксировать хэндшейк. Несуществующий `detour` внутри check не видит (дайлер инициализируется лениво, ошибка ожидается при подключении). |
| `private_key` | string | — (обязательно) | base64url без выравнивания, 32 байта; иначе `invalid private key`. |
| `short_id` | string\|[string] | пусто | Допустимые идентификаторы: hex до 16 символов. Пустой список — принимается только нулевой (пустой) идентификатор. Больше 16 символов — `panic` при создании (как у клиента). |
| `max_time_difference` | duration | — | Допустимое расхождение часов клиента и сервера; не задано — не проверяется. |

С Reality запрещены: `certificate`, `certificate_path`, `key`, `key_path`, `client_certificate_public_key_sha256`, `curve_preferences`, `certificate_provider`, `acme`, `ech`, kTLS вне Linux.

#### Встроенный ACME (acme, устаревшее)

Устарело в 1.14, удаление в 1.16: при использовании выводится предупреждение (не фатально). Замена — `certificate_provider` с типом `acme`, поля переносятся без изменений.

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `domain` | string\|[string] | — | Домены сертификата. Пусто — ACME выключен, нужны `certificate`/`key`. |
| `data_directory` | string | каталог certmagic | Где хранить данные ACME. Переменные окружения раскрываются, относительный путь — от рабочего каталога. По умолчанию `$XDG_DATA_HOME/certmagic` или `$HOME/.local/share/certmagic`. |
| `default_server_name` | string | — | Какой сертификат отдавать клиенту без SNI. |
| `email` | string | — | Почта аккаунта ACME. |
| `provider` | string | `letsencrypt` | `letsencrypt`, `zerossl` или URL каталога `https://…`; иное — ошибка. |
| `disable_http_challenge` | bool | `false` | Отключить HTTP-01. |
| `disable_tls_alpn_challenge` | bool | `false` | Отключить TLS-ALPN-01. |
| `alternative_http_port` | int | `0` (порт 80) | Порт слушателя для HTTP-01 вместо 80. |
| `alternative_tls_port` | int | `0` (порт 443) | Порт для TLS-ALPN-01; на него должен быть проброшен 443. |
| `external_account` | object | — | Привязка внешнего аккаунта (EAB): `key_id` (string), `mac_key` (string). |
| `dns01_challenge` | object | — | DNS-01; при его наличии прочие способы проверки не используются. Только `provider` и поля провайдера: поля `ttl`, `propagation_*`, `resolvers`, `override_domain` здесь не принимаются (ошибка `unknown field "ttl"`, проверено). |
| `profile` | string | — | В документации к `tls.acme` отсутствует, в коде есть. Профиль ACME; для Let's Encrypt при IP-адресе в `domain` автоматически `shortlived`. |

check встроенный ACME не запускает: выпуск сертификата и слушатели проверки — при старте.

### TLS поверх QUIC

Для QUIC (hysteria, hysteria2, tuic, V2Ray-транспорт `quic`, HTTP/3) из «нестандартного» TLS поддерживается только ECH. uTLS и Reality требуют стандартной конфигурации, которой у них нет: check с ними проходит (проверено для hysteria2), отказ ожидается при подключении. `fragment`, `record_fragment` и `spoof` к QUIC не применяются.

Исходники: option/tls.go, option/tls_acme.go, common/tls/client.go, common/tls/std_client.go, common/tls/utls_client.go, common/tls/reality_client.go, common/tls/ech.go, common/tls/system_client.go, common/tls/system_client_engine.go, common/tls/windows_client.go, common/tls/apple_client_stub.go, common/tls/server.go, common/tls/std_server.go, common/tls/reality_server.go, common/tls/acme.go, common/tlsspoof/spoof.go, common/tlsspoof/raw_windows.go, constant/tls.go, constant/timeout.go; документация: docs/configuration/shared/tls.md, docs/migration.md.

## Провайдеры сертификатов (certificate_provider)

с 1.14. Источник серверных сертификатов для входящего TLS. Задаётся двумя способами: элементом верхнеуровневого списка `certificate_providers` ([config.md](config.md#certificate_providers)), на который входящий ссылается строкой-тегом в `tls.certificate_provider`, либо встроенным объектом прямо в `tls.certificate_provider` (с `type`, без `tag`). Код поставщиков лежит в `service/`, но это не службы раздела `services`. Для Reality поставщик недоступен. Этот раздел — основное описание полей поставщиков; встроенный устаревший `tls.acme` описан выше, в [Встроенный ACME](#встроенный-acme-acme-устаревшее).

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `type` | string | — | `acme` (build-тег `with_acme`), `cloudflare-origin-ca`, `tailscale` (build-тег `with_tailscale`); в официальной сборке для Windows есть все три. Неизвестный или пустой — ошибка разбора. Ключ пишется только строчными (`"Type"` — `unknown field`). |
| `tag` | string | номер элемента | Только в списке верхнего уровня: повтор — ошибка разбора `duplicate certificate provider tag` (check). Только строчными. Во встроенном объекте не используется. |

Когда что проверяется: поля поставщика и его собственные ссылки (`http_client`, `endpoint`) — в конструкторе, их ловит check. Ссылку `tls.certificate_provider` входящего на несуществующий тег check пропускает (проверено), а запуск входящего падает: `certificate provider not found`. Выпуск сертификата идёт после запуска и зависит от сети.

### acme

Выпуск сертификатов по ACME (библиотека certmagic).

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `domain` | string\|[string] | — (обязательно) | Домены или IP-адреса; пусто — `missing domain`. Для IP-адресов у Let's Encrypt автоматически выбирается профиль `shortlived`. |
| `data_directory` | string | хранилище certmagic по умолчанию (`$XDG_DATA_HOME/certmagic` или `<домашний каталог>/.local/share/certmagic`) | Каталог данных ACME. Переменные окружения раскрываются (`os.ExpandEnv`, только `$VAR`), относительный путь — от рабочего каталога; создаётся при старте с правами 0700. |
| `default_server_name` | string | `""` | Какой сертификат отдавать клиенту без SNI. |
| `email` | string | `""` | Почта аккаунта ACME. |
| `provider` | string | `letsencrypt` | `letsencrypt`, `zerossl` или URL каталога `https://…` своего УЦ (регистр важен; `http://` — ошибка). Для `zerossl` нужен хотя бы один из `external_account.key_id`, `email`, `account_key`; при `email` без `external_account` учётные данные EAB запрашиваются у ZeroSSL автоматически. |
| `account_key` | string | `""` | с 1.14. PEM-ключ уже существующего аккаунта ACME. |
| `disable_http_challenge` | bool | `false` | Отключить HTTP-01. |
| `disable_tls_alpn_challenge` | bool | `false` | Отключить TLS-ALPN-01. |
| `alternative_http_port` | int | `0` (порт 80) | Слушать проверку HTTP-01 на этом порту вместо 80. |
| `alternative_tls_port` | int | `0` (порт 443) | Слушать TLS-ALPN-01 на этом порту; на него должен быть проброшен 443. |
| `external_account` | object | — | Привязка внешнего аккаунта (EAB): `key_id` (string), `mac_key` (string). Учитывается при непустом `key_id`. |
| `dns01_challenge` | object | — | [DNS-01](#dns-01-dns01_challenge), включая общие поля 1.14. При нём TLS-ALPN-01 (и, по поведению certmagic, HTTP-01) не используется. |
| `key_type` | string | тип certmagic по умолчанию | с 1.14. Тип ключа новых сертификатов: `ed25519`, `p256`, `p384`, `rsa2048`, `rsa4096` (регистр не важен). |
| `profile` | string | `""` | с 1.14. Профиль ACME; для Let's Encrypt с IP-адресом среди доменов по умолчанию `shortlived`. |
| `http_client` | string -> http_client \| object | прямое соединение | с 1.14. [HTTP-клиент](config.md#http_clients) для всех запросов к УЦ и к DNS-провайдеру. Неизвестный тег ловит check. |

### cloudflare-origin-ca

Сертификат Cloudflare Origin CA через API Cloudflare; перевыпуск за 30 дней до истечения.

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `domain` | string\|[string] | — (обязательно) | Имена в сертификате, допускаются шаблоны `*.`; IP-адрес — ошибка (check); шаблон должен покрывать многоуровневый домен. |
| `data_directory` | string | как у `acme` | Где хранить сертификат, ключ и метаданные; переменные окружения раскрываются. |
| `api_token` | string | `""` | API-токен Cloudflare с правом «Zone / SSL and Certificates / Edit». |
| `origin_ca_key` | string | `""` | Ключ Origin CA. Обязательно ровно одно из `api_token` и `origin_ca_key`: оба или ни одного — ошибка (check). |
| `request_type` | string | `origin-rsa` | `origin-rsa` или `origin-ecc` (P-256); регистр не важен. |
| `requested_validity` | int | `5475` | Срок в днях: `7`, `30`, `90`, `365`, `730`, `1095`, `5475`; иное — ошибка разбора; `0` — по умолчанию. |
| `http_client` | string -> http_client \| object | прямое соединение | HTTP-клиент для запросов к API; неизвестный тег ловит check. |

### tailscale

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `endpoint` | string -> endpoint | — (обязательно) | Тег существующего эндпоинта `tailscale`; иначе check: `initialize certificate provider[0]: endpoint not found` (проверено) или `endpoint is not Tailscale`. В консоли tailnet должны быть включены MagicDNS и HTTPS. |

Исходники: option/certificate_provider.go, option/acme.go, option/tls_acme.go, option/origin_ca.go, option/tailscale.go (`TailscaleCertificateProviderOptions`), option/options.go (`checkCertificateProviders`), adapter/certificate/manager.go, adapter/certificate/registry.go, service/acme/service.go, service/origin_ca/service.go, protocol/tailscale/certificate_provider.go, common/tls/std_server.go (`newCertificateProvider`, `sharedCertificateProvider.Start`), include/acme*.go, include/tailscale*.go; документация: docs/configuration/shared/certificate-provider/.

## DNS-01 (dns01_challenge)

Проверка владения доменом через TXT-запись. Используется в `certificate_provider` типа `acme` и во встроенном `tls.acme`. При наличии блока прочие способы проверки отключаются.

Общие поля. `provider` есть везде; `ttl`, `propagation_delay`, `propagation_timeout`, `resolvers`, `override_domain` — с 1.14 и только у поставщика `acme` (во встроенном `tls.acme` — ошибка разбора `unknown field`). Ошибки значений ловит check:

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `provider` | string | — (обязательно) | `alidns`, `cloudflare`, `acmedns`; иное или пустое — ошибка разбора. |
| `ttl` | duration | по умолчанию certmagic | TTL временной TXT-записи; отрицательное — ошибка. |
| `propagation_delay` | duration | `0` | Пауза после создания записи перед проверками распространения; отрицательное — ошибка. |
| `propagation_timeout` | duration | по умолчанию certmagic | Сколько ждать распространения; `-1` — не проверять; меньше `-1` — ошибка. |
| `resolvers` | string\|[string] | `[]` | DNS-резолверы для проверки распространения. |
| `override_domain` | string | `""` | Другое имя для записи проверки (когда `_acme-challenge` делегирован в другую зону). |

Поля провайдеров:

| Провайдер | Поле | Тип | Смысл |
|---|---|---|---|
| `alidns` | `access_key_id` | string | ключ доступа Alibaba Cloud |
| `alidns` | `access_key_secret` | string | секрет |
| `alidns` | `region_id` | string | регион |
| `alidns` | `security_token` | string | с 1.13; токен временных учётных данных STS |
| `cloudflare` | `api_token` | string | API-токен |
| `cloudflare` | `zone_token` | string | с 1.13; токен с правом `Zone:Read`, позволяет ограничить `api_token` одной зоной |
| `acmedns` | `username` | string | с 1.13 (весь провайдер); сервер ACME-DNS; все четыре поля обязательны, проверка — при выпуске |
| `acmedns` | `password` | string | |
| `acmedns` | `subdomain` | string | |
| `acmedns` | `server_url` | string | |

Исходники: option/tls_acme.go, option/acme.go, constant/dns.go (`DNSProvider*`), service/acme/service.go, common/tls/acme.go; документация: docs/configuration/shared/dns01_challenge.md.

## V2Ray-транспорты (transport)

Объект `transport` у исходящих и входящих vmess, vless, trojan. Выбор по полю `type`: `http`, `ws`, `quic`, `grpc`, `httpupgrade`. Остальные поля зависят от типа, лишние поля — ошибка разбора (например, `host` у `ws`: `unknown field "host"`).

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `type` | string | — (обязательно при любых других полях) | `http`, `ws`, `quic`, `grpc`, `httpupgrade`; определяет набор остальных полей (подразделы ниже). |

- Не поддерживаются: XHTTP/SplitHTTP, mKCP, DomainSocket, отдельный «TCP»-транспорт с обфускацией заголовка (простой HTTP объединён с транспортом `http`), шифрование и заголовки QUIC из v2ray. Неизвестный `type` — ошибка разбора `unknown transport type: xhttp`.
- Пустой объект `"transport": {}` принимается как «без транспорта»; объект с полями, но без `type` — `unknown transport type: ` (проверено).
- ALPN по умолчанию (если `tls.alpn` пуст): `http` и `grpc` — `h2`; `ws` и `httpupgrade` — `http/1.1`; `quic` — `h3`. Явный `alpn` с `h2` у `ws`/`httpupgrade` может заставить сервер ответить по HTTP/2 и сломать Upgrade.

### http

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `host` | string\|[string] | — | Клиент берёт случайное имя из списка; сервер при непустом списке сверяет `Host`. |
| `path` | string | — | Путь запроса; сервер сверяет, но, как в V2Ray, клиенту разрешён произвольный суффикс. |
| `method` | string | клиент: `PUT` | Метод; сервер сверяет, если задан. |
| `headers` | object (string → string\|[string]) | — | Дополнительные заголовки; сервер пишет их в ответ. |
| `idle_timeout` | duration | `0` | HTTP/2: у клиента — через сколько тишины послать PING для проверки (0 — не проверять); у сервера — когда закрыть простаивающее соединение. |
| `ping_timeout` | duration | `15s` | HTTP/2-клиент: сколько ждать ответа на PING до закрытия. |

Без TLS — HTTP/1.1, с TLS — HTTP/2. TLS не обязателен.

### ws

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `path` | string | `/` | Путь; сервер сверяет. |
| `headers` | object (string → string\|[string]) | — | Заголовки; `Host` отсюда становится хостом запроса. Клиент по умолчанию шлёт `User-Agent: Go-http-client/1.1`. |
| `max_early_data` | int | `0` | Сколько байт полезной нагрузки передать ещё в запросе рукопожатия; `0` — выключено. |
| `early_data_header_name` | string | — | Где передавать ранние данные: пусто — в пути; `Sec-WebSocket-Protocol` — совместимо с Xray. Должно совпадать с сервером. |

### quic

Полей нет (`{"type": "quic"}`). TLS обязателен: без него check — `quic: TLS required`. Требует сборку с `with_quic` (в официальной есть). Дополнительного шифрования и заголовков из v2ray нет. uTLS и Reality поверх QUIC не работают (см. [TLS поверх QUIC](#tls-поверх-quic)).

### grpc

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `service_name` | string | `""` | Путь запросов — `/<service_name>/Tun`; имя экранируется как один сегмент пути. |
| `idle_timeout` | duration | `0` | Облегчённая реализация: как у транспорта `http`. Стандартный gRPC: интервал keepalive-пинга при отсутствии активности. |
| `ping_timeout` | duration | `15s` | Облегчённая: как у `http`. Стандартный: ожидание ответа на keepalive. |
| `permit_without_stream` | bool | `false` | Только стандартный gRPC: пинговать и без активных потоков. |

Стандартный gRPC входит только в сборки с тегом `with_grpc`. Официальная сборка 1.14.2 его не содержит (в `sing-box version` нет `with_grpc`), поэтому всегда работает облегчённая реализация поверх HTTP/2, а `permit_without_stream` принимается и не действует.

### httpupgrade

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `host` | string | `tls.server_name`, иначе адрес сервера | Хост запроса; только строка (массив — ошибка разбора). Сервер сверяет, если задан. |
| `path` | string | `/` | Путь; сервер сверяет. |
| `headers` | object (string → string\|[string]) | — | Дополнительные заголовки; сервер пишет их в ответ. |

Клиент шлёт `GET` с `Connection: Upgrade` и `Upgrade: websocket`, после ответа 101 идёт сырой поток без кадров WebSocket.

Исходники: option/v2ray_transport.go, constant/v2ray.go, transport/v2ray/transport.go, transport/v2ray/grpc.go, transport/v2ray/grpc_lite.go, transport/v2ray/quic.go, transport/v2rayhttp/client.go, transport/v2rayhttp/server.go, transport/v2raywebsocket/client.go, transport/v2rayhttpupgrade/client.go, transport/v2raygrpclite/client.go, transport/v2raygrpclite/server.go, transport/v2rayquic/client.go; документация: docs/configuration/shared/v2ray-transport.md.

## Мультиплексирование (multiplex)

Объект `multiplex` у исходящих и входящих shadowsocks, vmess, vless, trojan: несколько логических потоков в одном соединении (библиотека sing-mux). Входящий определяет протокол сам.

Исходящий:

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `enabled` | bool | `false` | Включить. При `false` содержимое блока не проверяется. |
| `protocol` | string | `h2mux` | `h2mux`, `smux`, `yamux`; иное — check: `unknown protocol`. |
| `max_connections` | int | `0` | Предел числа несущих соединений. По документации несовместим с `max_streams`. |
| `min_streams` | int | `0` | Сколько потоков набрать в соединении, прежде чем открыть новое. По документации несовместим с `max_streams`. |
| `max_streams` | int | `0` | Предел потоков в соединении, после которого открывается новое. По документации несовместим с `max_connections` и `min_streams`. |
| `padding` | bool | `false` | Дополнять трафик заполнением (сервер sing-box 1.3-beta9 и новее). |
| `brutal` | object | — | [TCP Brutal](#tcp-brutal-brutal). |

Входящий:

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `enabled` | bool | `false` | Принимать мультиплексированные соединения. |
| `padding` | bool | `false` | Отвергать соединения без заполнения. |
| `brutal` | object | — | TCP Brutal на стороне сервера. |

Замечания:

- Несовместимость `max_streams` с `max_connections`/`min_streams` check не проверяет (проверено).
- Если ни `max_connections`, ни `max_streams` не заданы, действует политика библиотеки sing-mux; её значения в дереве sing-box не видны (по памяти исходников sing-mux — `min_streams` = 8, не проверено).
- У исходящего shadowsocks при включённом `udp_over_tcp` мультиплексор не создаётся вовсе: `multiplex` молча игнорируется.
- Поля `protocol` у входящего нет (ошибка разбора `unknown field "protocol"`).

Исходники: option/multiplex.go, common/mux/client.go, common/mux/router.go, protocol/shadowsocks/outbound.go; документация: docs/configuration/shared/multiplex.md.

## TCP Brutal (brutal)

Алгоритм управления перегрузкой с фиксированной скоростью для мультиплексированных соединений. На сервере нужен Linux с модулем ядра `brutal`.

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `enabled` | bool | `false` | Включить. |
| `up_mbps` | int | — (обязательно) | Скорость отдачи, Мбит/с. Ниже минимума библиотеки (0 — точно ниже, 1 — допустимо) — ошибка при создании `brutal: invalid upload speed`. |
| `down_mbps` | int | — (обязательно) | Скорость приёма, Мбит/с; аналогично (`invalid download speed`). |

На Windows: у входящего `multiplex.brutal` check завершается ошибкой `TCP Brutal is only supported on Linux`; у исходящего check проходит (проверено).

Исходники: option/multiplex.go (`BrutalOptions`), common/mux/client.go, common/mux/router.go, constant/speed.go; документация: docs/configuration/shared/tcp-brutal.md.

## UDP over TCP (udp_over_tcp)

Собственный протокол SagerNet для передачи UDP внутри TCP-потока прокси (к shadowsocks отношения не имеет). Поле у исходящих shadowsocks, socks, naive. Принимающая сторона ничего не настраивает: протокол распознают входящие shadowsocks, socks, http, mixed, naive, vless, vmess, anytls, snell, tuic. Можно записать просто `true`, это равно `{"enabled": true}` с версией по умолчанию.

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `enabled` | bool | `false` | Включить. |
| `version` | int | `2` | Версия протокола, `1` или `2`. Другие значения check не отвергает (проверено для `3`). Неизвестные ключи в объекте — ошибка разбора. |

Версия 1 обращается к служебному адресу `sp.udp-over-tcp.arpa`, версия 2 — к `sp.v2.udp-over-tcp.arpa` и умеет режим «connect» (поток к одному адресату без адреса в каждом пакете).

Исходники: option/udp_over_tcp.go, protocol/shadowsocks/outbound.go, protocol/socks/outbound.go, protocol/naive/outbound.go, route/route.go; документация: docs/configuration/shared/udp-over-tcp.md.

## Параметры HTTP/2 (HTTP2 Fields)

с 1.14. Плоский набор полей у HTTP-клиента (`version` 2 или не задан) и у сервиса hysteria-realm. Также входит в [параметры QUIC](#параметры-quic-quic-fields).

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `idle_timeout` | duration | `0` | Документация: тайм-аут простоя соединения. По коду HTTP/2-клиента значение уходит в `PingTimeout` — сколько ждать ответа на PING; в QUIC — предельный простой соединения. |
| `keep_alive_period` | duration | `0` | Период keep-alive. В HTTP/2-клиенте — через сколько тишины посылать PING; в QUIC — интервал keep-alive. |
| `stream_receive_window` | size | умолчание библиотеки | Окно приёма потока. |
| `connection_receive_window` | size | умолчание библиотеки | Окно приёма соединения. |
| `max_concurrent_streams` | int | `0` | Предел одновременных потоков на соединение (в QUIC — входящих). |

Исходники: option/http.go (`HTTP2Options`), common/httpclient/http2_config.go; документация: docs/configuration/shared/http2.md.

## Параметры QUIC (QUIC Fields)

с 1.14. Плоский набор полей у исходящих и входящих hysteria, hysteria2, tuic и у HTTP-клиента с `version: 3`. Содержит все [параметры HTTP/2](#параметры-http2-http2-fields) плюс:

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `initial_packet_size` | int | умолчание quic-go | Начальный размер QUIC-пакета. |
| `disable_path_mtu_discovery` | bool | `false` | Отключить определение MTU пути. |

В QUIC-протоколах (hysteria, hysteria2, tuic, входящих и исходящих) поля HTTP/2 значат: `idle_timeout` — предельный простой QUIC-соединения, `keep_alive_period` — интервал keep-alive, `stream_receive_window`/`connection_receive_window` — окна приёма потока и соединения, `max_concurrent_streams` — предел одновременных **входящих** потоков. Незаданное или нулевое значение означает умолчание протокола, а не «ноль»: у hysteria v1 это окно потока 8 МБ, окно соединения 20 МБ, простой 30s, keep-alive 10s ([inbounds.md](inbounds.md#hysteria)); у исходящего hysteria2 с имитацией Chrome — значения Chrome, причём `idle_timeout` зафиксирован на 30 секундах ([outbounds.md](outbounds.md#hysteria2)).

У hysteria v1 эти поля заменяют устаревшие `recv_window_conn`, `recv_window`, `recv_window_client`, `max_conn_client`, `disable_mtu_discovery` (удаление в 1.16). Перенос в коде идёт не так, как советует документация, см. [deprecations.md](deprecations.md#hysteria-v1-см-inboundsmd-outboundsmd).

Исходники: option/http.go (`QUICOptions`), option/hysteria.go, option/hysteria2.go, option/tuic.go, protocol/hysteria/quic.go, common/httpclient/http3_transport.go; документация: docs/configuration/shared/quic.md.

## HTTP-клиент (http_client)

с 1.14. Единая настройка собственных HTTP-запросов sing-box: загрузка удалённых rule-set (`http_client` набора и `route.default_http_client` — [route.md](route.md#remote)), поставщики `acme` и `cloudflare-origin-ca` ([выше](#провайдеры-сертификатов-certificate_provider)), `verify_client_url` у DERP, дашборд сервиса `api`, `realm` у hysteria2. Ссылка на клиент — строка (тег элемента верхнеуровневого `http_clients`) или встроенный объект с теми же полями без `tag`.

Основное описание — в [config.md](config.md#http_clients): таблица полей (`tag`, `engine`, `version`, `disable_version_fallback`, `headers`, поля [HTTP/2](#параметры-http2-http2-fields) при `version` 2 или без него, поля [QUIC](#параметры-quic-quic-fields) при `version` 3, `tls` — [исходящий TLS](#исходящий-tls-клиент), [dial-поля](#поля-подключения-dial)), откат версий, разница между тегом и объектом, выбор клиента по умолчанию и что когда проверяется. Главное для этого файла: без `detour` клиент подключается напрямую, мимо маршрутизации; HTTP-клиент rule-set'а создаётся при старте, поэтому check пропускает несуществующий тег, `engine: apple` на Windows и `version: 3` с uTLS (проверено) — всё это падает только при старте или загрузке.

Исходники: option/http.go (`HTTPClientOptions`, `HTTPClient`), common/httpclient/client.go, common/httpclient/manager.go; документация: docs/configuration/shared/http-client.md.

## Pre-match

Прогон правил маршрутизации до установления соединения для L3-входящих (tun, эндпоинты wireguard и tailscale). Что делает в pre-match каждое действие — L3-пересылка `route` в `bridge` и эндпоинты, сниффинг первого UDP-пакета, обход ядром через `bypass` с `auto_redirect` на Linux, остановка на действиях, которым не хватает данных, — описано в [route.md](route.md#pre-match), там основное описание. На Windows `bypass` недоступен, `bridge` работает через WinDivert.

Исходники: route/route.go (`PreMatch`); документация: docs/configuration/shared/pre-match.md.

## Поиск соседей (neighbor)

с 1.14. Сопоставление устройств локальной сети по MAC-адресу и имени хоста (элементы правил `source_mac_address`, `source_hostname`). Включается автоматически при наличии таких элементов или `neighbor_domain` у DNS-сервера `local`; принудительно — `route.find_neighbor`, пути аренд DHCP — `route.dhcp_lease_files` ([route.md](route.md), [dns.md](dns.md)). Реализация есть для Linux (имена — из файлов аренд dnsmasq, odhcpd, ISC dhcpd, Kea), macOS (отдельная версия с системным расширением) и Android (графический клиент, root, VPNHotspot). На Windows резолвера соседей нет: sing-box молча работает без него, и такие элементы правил не совпадают.

Исходники: route/router.go, route/neighbor_resolver_linux.go, route/neighbor_resolver_darwin.go, route/neighbor_resolver_stub.go, option/route.go; документация: docs/configuration/shared/neighbor.md.

## Состояние Wi-Fi (wifi_state)

Отслеживание текущей сети Wi-Fi для элементов правил `wifi_ssid` и `wifi_bssid` ([route.md](route.md)). Платформы: Android и Apple (графические клиенты), Linux (с 1.13; по приоритету NetworkManager, IWD, wpa_supplicant, ConnMan), Windows (с 1.13; WLAN API). Отдельных полей конфигурации нет.

Исходники: common/settings/wifi_windows.go, common/settings/wifi_linux.go, route/network.go; документация: docs/configuration/shared/wifi-state.md.

## Что ловит check, а что всплывает позже

Сводка по блокам этого файла (проверено на `sing-box.exe` 1.14.2 для Windows, если не сказано иное).

| Ситуация | check | Когда проявится |
|---|---|---|
| неизвестное поле, неверный тип, неизвестное значение перечисления | ошибка разбора | — |
| неизвестное поле внутри объекта `domain_resolver` | проходит | никогда (молча игнорируется) |
| `routing_mark` или `bind_address_no_port` в dial-полях на Windows | ошибка | — |
| `routing_mark` в listen-полях вне Linux | проходит | никогда: молча игнорируется |
| `netns` в listen-полях; `netns` в dial-полях на Windows | проходит | при старте (listen) или подключении (dial) |
| `domain_resolver` на несуществующий DNS-сервер (доменный адрес) | ошибка | — |
| нет `domain_resolver` и `route.default_domain_resolver` при двух и более DNS-серверах, доменном адресе и без `detour` | фатально (устаревшее), обход — `ENABLE_DEPRECATED_MISSING_DOMAIN_RESOLVER=true`; у naive, openvpn, openconnect, tailscale, derp — ошибка без обхода | — |
| DNS-сервер с доменным адресом без `domain_resolver` и без `detour` | ошибка (`route.default_domain_resolver` не помогает) | — |
| dial `domain_strategy` при доменном адресе без `detour` | фатально, обход — `ENABLE_DEPRECATED_LEGACY_DOMAIN_STRATEGY_OPTIONS=true` | — |
| `detour` на несуществующий исходящий или кольцо | проходит | при старте |
| `detour` исходящего на «пустой» direct | проходит | при первом соединении |
| `detour` в listen-полях на несуществующий входящий | проходит | при каждом соединении |
| конфликт `network_strategy` с привязкой или TFO | ошибка | — |
| ошибки TLS-блока (версии, шифры, kTLS вне Linux, pin вместе с `certificate`, неподдерживаемое поле движка `windows`, uTLS-отпечаток, Reality без uTLS, spoof без SNI) | ошибка | — |
| отсутствующий файл `certificate_path`/`key_path` | ошибка | — |
| `short_id` Reality длиннее 16 hex-символов | аварийное завершение (`panic`, код 2) | — |
| Reality-сервер без `handshake` | проходит | при подключении |
| `certificate_provider` на несуществующий тег | проходит | при старте |
| поставщик `acme`/`cloudflare-origin-ca`: неизвестный тег `http_client`, нет `domain`, IP в `domain` у Origin CA, оба ключа Cloudflare или ни одного, ZeroSSL без email/EAB/ключа, провайдер `http://`, `propagation_timeout` меньше `-1` | ошибка | — |
| поставщик `tailscale` без эндпоинта или с эндпоинтом не того типа | ошибка | — |
| uTLS/Reality поверх QUIC | проходит | при подключении |
| `transport.type` вне списка | ошибка разбора | — |
| `quic`-транспорт без TLS | ошибка | — |
| `multiplex.protocol` вне списка, `brutal` со скоростью 0 | ошибка | — |
| `max_streams` вместе с `max_connections`/`min_streams` | проходит | поведение библиотеки |
| входящий `multiplex.brutal` на Windows | ошибка | — |
| `udp_over_tcp.version` вне 1–2 | проходит | не проверялось |
| HTTP-клиент rule-set'а: несуществующий тег, `engine: apple`, `version: 3` с uTLS | проходит | при старте или загрузке |
| `proxy_protocol` в listen-полях | проходит | при открытии слушателя |

## Расхождения документации и кода

1. `listen`: документация помечает поле обязательным, код по умолчанию слушает `127.0.0.1`.
2. `tls.insecure` у входящего не описан в документации: без сертификата и ключа сервер выпускает самоподписанный сертификат на лету; вместе с ACME или провайдером — ошибка.
3. Dial-поле `protect_path` не описано в документации.
4. `domain_resolver`: документация говорит «формат действия route DNS-правила», в коде семь полей, а неизвестные ключи молча игнорируются.
5. Dial `domain_strategy`: документация обещала удаление в 1.14.0; в 1.14.2 поле разбирается, но в действующих случаях без переменной окружения фатально, а в остальных молча игнорируется. В deprecated.md пункта нет.
6. Конфликт `network_strategy`: код добавляет к перечисленным в документации полям `tcp_fast_open`, и проверка работает на всех платформах.
7. `fallback_delay`: документация — «только при `domain_strategy` или `network_strategy`»; по коду задержка участвует в любом параллельном наборе адресов после резолва (без `detour` и TFO). Сам алгоритм набора находится в библиотеке sing и по дереву sing-box до конца не проверен.
8. `connect_timeout`: умолчание 5s есть только в коде.
9. `reuse_addr` в dial-полях по коду применяется лишь к UDP-сокетам исходящего; `tcp_multi_path` — лишь к IPv4-дайлеру.
10. uTLS: документация пишет, что старые отпечатки `chrome_*` «удалены»; код принимает их как `chrome`, schema.json тоже их перечисляет.
11. Reality: `short_id` и `handshake` помечены обязательными, но пустые значения проходят; `short_id` длиннее 16 символов роняет процесс вместо ошибки. Требование `utls.enabled` для клиента в документации явно не указано.
12. `dns01_challenge`: поля 1.14 (`ttl`, `propagation_*`, `resolvers`, `override_domain`) документация не ограничивает провайдером, а встроенный `tls.acme` их не принимает. У встроенного ACME в коде есть недокументированное поле `profile`.
13. ECH `pq_signature_schemes_enabled`/`dynamic_record_sizing_disabled` «удалены в 1.13», но разбираются: `true` — ошибка, `false` — молча.
14. HTTP/2 `idle_timeout`: документация — тайм-аут простоя, в HTTP/2-клиенте код использует его как тайм-аут ответа на PING, а `keep_alive_period` — как интервал проверки.
15. `multiplex`: взаимоисключение `max_streams` и `max_connections`/`min_streams` задокументировано, но не проверяется.
16. Исходящий `tls.certificate` заменяет корневые сертификаты целиком (системные и из раздела `certificate` не используются), а `server_name` по умолчанию берётся из `server` — в документации этого нет.
17. У входящего TLS хэши `client_certificate_public_key_sha256` без явного `client_authentication` не действуют.
18. `data_directory` поставщиков `acme` и `cloudflare-origin-ca` (и встроенного `tls.acme`) раскрывает переменные окружения (`os.ExpandEnv`) — в документации этого нет.
19. `routing_mark` в listen-полях: документация называет поле «только Linux», не уточняя, что на других ОС оно молча игнорируется (в dial-полях — ошибка check).

Исходники сводок: cmd/sing-box/cmd_check.go, box.go, adapter/outbound/manager.go (зависимости при старте), а также файлы, перечисленные в разделах выше.
