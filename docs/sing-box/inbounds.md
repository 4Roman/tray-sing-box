# Входящие (inbounds) — sing-box 1.14.2

Справочник по элементам списка `inbounds` sing-box **1.14.2**: общие поля и особенности разбора, поля прослушивания (listen), пользователи по протоколам, TLS у серверных входящих, все типы входящих и подробно `tun`, включая его поведение на Windows. Факты сверены с исходниками 1.14.2 (`option/*.go`, `protocol/**`) и с библиотекой sing-tun той же сборки. Опыты — `sing-box check` и `sing-box format` официального `sing-box.exe` 1.14.2 для Windows, без запуска.

Смежные файлы: блоки listen, TLS, dial, multiplex, transport, UDP NAT и QUIC — [shared.md](shared.md); HTTP-клиент — [config.md](config.md#http_clients); исходящие и эндпоинты (wireguard, tailscale и openvpn-server тоже принимают входящие соединения) — [outbounds.md](outbounds.md); правила маршрутизации, действия `sniff`, `hijack-dns`, `resolve`, pre-match, rule-set, `auto_detect_interface` — [route.md](route.md); DNS — [dns.md](dns.md); верхний уровень конфига и правила разбора JSON — [config.md](config.md); устаревшее — [deprecations.md](deprecations.md); команды — [cli.md](cli.md).

## Условные обозначения

- Типы записаны как типы JSON: `string`, `int`, `bool`, `object`, `[object]`.
- `string|[string]` — поле типа `badoption.Listable`: одно значение без скобок или массив.
- `duration` — строка в синтаксисе длительностей Go (`"300ms"`, `"5m"`); число вместо строки — ошибка разбора. Исключение — `udp_timeout`, см. [listen](shared.md#поля-прослушивания-listen).
- `prefix` — IP-префикс CIDR (`"172.19.0.1/30"`); адрес без `/` — ошибка разбора (проверено). `ip` — IP-литерал без порта и без имени хоста.
- `mark` — число или строка с числом в записи Go (`1234`, `"0x2023"`).
- `size` — объём памяти (`"8 MB"`), подробности в [shared.md](shared.md).
- `-> inbound`, `-> outbound`, `-> rule-set`, `-> dns server`, `-> http_client` — ссылка по тегу.
- «с 1.X» — поле или тип появились в 1.X (отмечается для 1.10 и новее).
- «check» — `sing-box check`: разбор JSON и `box.New` (создание всех объектов, чтение файлов), без `Start`. «При старте» — ошибка в `Start`, check её не видит. «При подключении» — ошибка на каждом соединении, её не видят ни check, ни старт. «Молча» — принимается и не действует.
- «Проверено» — опыт на `sing-box.exe` 1.14.2 для Windows; «по коду» — вывод из исходников без запуска.

## Общие поля и разбор JSON

У каждого элемента `inbounds[]` два общих поля; остальные зависят от `type`.

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `type` | string | — (обязательно) | Тип входящего. Неизвестный — ошибка разбора `unknown inbound type: X`. Значение чувствительно к регистру: `"Mixed"` — ошибка (проверено). |
| `tag` | string | номер элемента (`"0"`, `"1"`, …) | Имя входящего. На него ссылаются условие `inbound` в правилах маршрутизации и DNS, поле `detour` других входящих, логи. |

Особенности разбора (проверено):

- Ключи `type` и `tag` пишутся строго строчными. `"Type"` или `"Tag"` дают ошибку `inbounds[0].Type: json: unknown field "Type"`: сначала ключ опознаётся без учёта регистра, но из остатка объекта исключается только точное имя, и остаток его отвергает.
- Все прочие ключи, включая вложенные, сопоставляются без учёта регистра: `"Listen_Port"`, `"LISTEN"`, `"Auto_Route"`, `"Users": [{"USERNAME": …}]` понимаются как обычные. Работают и юникодные «двойники» из правил свёртки Go: ключ `"stacK"` (знак Кельвина) распознан как `stack`. Общее правило — в [config.md](config.md).
- Неизвестный ключ — ошибка разбора (`json: unknown field`). Исключение: в объекте `obfs` типа `salamander` у hysteria2 лишние ключи молча отбрасываются (`format` их не выводит).
- Теги входящих проверяются на уникальность среди входящих (`duplicate inbound tag: m`), с учётом подставленных номеров. Пространство тегов входящих отдельное от исходящих и эндпоинтов.
- `sing-box format` выводит пользователей socks, http, mixed и naive с ключами `Username`/`Password`: у структуры `auth.User` нет json-тегов. При чтении это то же самое, что `username`/`password`.
- Поля, удалённые из listen-полей в 1.13 (`sniff` и др.), — ошибка разбора для всех типов с listen-полями и ошибка создания у `tun`, см. [ниже](#удалённые-поля-listen).

Исходники: option/inbound.go (`Inbound.UnmarshalJSONContext`), option/options.go (`checkInbounds`), box.go, include/registry.go, adapter/inbound/registry.go.

## Сводка типов входящих

«detour-цель» — может ли входящий принять соединение, переданное другим входящим через `detour` (см. [detour и инъекция](#detour-и-инъекция-соединений)).

| Тип | Что это | Сеть | TLS | detour-цель | Платформы, сборка | Версия |
|---|---|---|---|---|---|---|
| `direct` | Туннель: принимает трафик и отправляет на исходный или заданный адрес (проброс порта) | TCP, UDP | нет | по докам нет, по коду TCP да | все | |
| `mixed` | SOCKS4, SOCKS4a, SOCKS5 и HTTP-прокси на одном порту | TCP (UDP через SOCKS5 UDP ASSOCIATE) | необязателен (в доках не описан) | TCP | все | |
| `socks` | SOCKS4, SOCKS4a, SOCKS5 | TCP (UDP через UDP ASSOCIATE) | нет | TCP | все | |
| `http` | HTTP-прокси (CONNECT и обычные запросы) | TCP | необязателен | TCP | все | |
| `shadowsocks` | Сервер Shadowsocks: один ключ, много пользователей или реле | TCP, UDP | нет | TCP | все | |
| `vmess` | Сервер VMess | TCP | необязателен | TCP | все | |
| `trojan` | Сервер Trojan с fallback | TCP | необязателен (нужен для `fallback_for_alpn`) | TCP | все | |
| `naive` | Сервер NaiveProxy: HTTP/2 CONNECT и HTTP/3 | TCP, UDP (QUIC) | обязателен для UDP | нет | все; HTTP/3 — `with_quic` | |
| `hysteria` | Hysteria v1 | QUIC | обязателен | нет | `with_quic` | |
| `shadowtls` | ShadowTLS v1–v3 | TCP | свой механизм | TCP | все | |
| `tuic` | TUIC v5 | QUIC | обязателен | нет | `with_quic` | |
| `hysteria2` | Hysteria2 | QUIC | обязателен | нет | `with_quic` | |
| `vless` | Сервер VLESS | TCP | необязателен | TCP | все | |
| `anytls` | Сервер AnyTLS | TCP | необязателен | TCP | все | с 1.12 |
| `snell` | Сервер Snell v5/v6 | TCP | нет | TCP | все | с 1.14 |
| `tun` | Виртуальный сетевой адаптер (L3) | IP | нет | нет | Linux, Windows, macOS; Android и iOS через графические клиенты | |
| `redirect` | Прозрачный прокси через `REDIRECT` | TCP | нет | по докам нет, по коду TCP да | Linux, macOS | |
| `tproxy` | Прозрачный прокси через TPROXY | TCP, UDP | нет | по докам нет, по коду TCP да | Linux | |
| `cloudflared` | Встроенный клиент Cloudflare Tunnel; слушающего сокета нет | TCP, UDP, ICMP от туннеля | нет | нет | `with_cloudflared` | с 1.14 |
| `shadowsocksr` | Удалён в 1.6 | — | — | — | — | — |

Официальная сборка 1.14.2 для Windows содержит теги `with_quic`, `with_gvisor`, `with_cloudflared` и др. (`sing-box version`), поэтому все типы доступны. Без `with_quic` hysteria, tuic и hysteria2 создаются с ошибкой `QUIC is not included in this build, rebuild with -tags with_quic`; без `with_cloudflared` — `Cloudflared is not included in this build, rebuild with -tags with_cloudflared`. `shadowsocksr` разбирается как shadowsocks, но создание всегда даёт `ShadowsocksR is deprecated and removed in sing-box 1.6.0` (проверено).

Типы серверных протоколов (shadowsocks, vmess, trojan, vless, naive, hysteria, tuic, hysteria2, shadowtls, anytls, snell) нужны для роли сервера; клиенту на Windows обычно достаточно `tun` и `mixed`/`socks`/`http`.

Исходники: include/registry.go, include/quic.go, include/quic_stub.go, include/cloudflared.go, include/cloudflared_stub.go, constant/proxy.go, constant/err.go.

## Поля прослушивания (listen)

Общий набор полей для всех входящих со своим сокетом: direct, mixed, socks, http, shadowsocks, vmess, trojan, naive, hysteria, shadowtls, tuic, hysteria2, vless, anytls, snell, redirect, tproxy. Поля записываются в объект входящего плоско: `listen`, `listen_port`, `bind_interface`, `routing_mark`, `reuse_addr`, `netns`, `tcp_fast_open`, `tcp_multi_path`, `disable_tcp_keep_alive`, `tcp_keep_alive`, `tcp_keep_alive_interval`, `udp_fragment`, `udp_timeout`, `detour`. Полная таблица с умолчаниями и поведением на Windows — в [shared.md](shared.md#поля-прослушивания-listen): там же описание для других владельцев (сервисы, openvpn-server).

У `tun` и `cloudflared` этих полей нет: `listen` у `tun` — ошибка `unknown field "listen"` (проверено), хотя документация tun ссылается на listen-поля.

Главное для входящих: без `listen` слушается `127.0.0.1` (документация называет поле обязательным); `udp_fragment` по умолчанию `true` у direct, hysteria, hysteria2, tuic; `routing_mark` вне Linux молча игнорируется; `netns` на Windows проходит check, но по коду роняет старт; `udp_timeout` можно писать и целым числом секунд.

### Удалённые поля listen

`sniff`, `sniff_override_destination`, `sniff_timeout`, `domain_strategy`, `udp_disable_domain_unmapping` удалены в 1.13: у типов с listen-полями это ошибка разбора, у `tun` — ошибка создания. `proxy_protocol` и `proxy_protocol_accept_no_header` удалены в 1.6: check их пропускает, ошибка — при открытии TCP-слушателя. Сообщения и замены — в [shared.md](shared.md#поля-прослушивания-listen) и [deprecations.md](deprecations.md#listen-поля-входящих-listenoptions-см-sharedmd).

### detour и инъекция соединений

`detour` во входящем A означает: принятое A соединение не маршрутизируется, а передаётся входящему B, как если бы B принял его сам. Типичный случай — `shadowtls` снимает свою обёртку и отдаёт поток `shadowsocks`, слушающему только на `127.0.0.1`.

- Цель должна уметь принимать чужие TCP-соединения. По документации это mixed, socks, http, shadowsocks, vmess, trojan, shadowtls, vless, anytls, snell. По коду такой же метод есть ещё у direct, redirect и tproxy. У tun, naive, hysteria, tuic, hysteria2, cloudflared его нет.
- UDP-инъекцию не поддерживает ни один входящий: UDP-сессия входящего с `detour` (например, direct или hysteria) завершается ошибкой `inbound detour is not UDP injectable`.
- Все ошибки — при подключении: `inbound detour not found: X` (тега нет), `inbound detour is not TCP injectable: X`, `routing loop on detour: X` (цель совпадает с предыдущим входящим). check и старт тег не проверяют (проверено для несуществующего тега).
- После передачи в метаданных соединения входящим считается цель; правило `inbound` видит тег цели.

Исходники: option/inbound.go (`ListenOptions`, `InboundOptions`, `UDPTimeoutCompat`), common/listener/listener.go, common/listener/listener_tcp.go, common/listener/listener_udp.go, route/route.go (`routeConnection`, `routePacketConnection`), adapter/inbound.go (`TCPInjectableInbound`); библиотека sing: common/control (`RoutingMark`, `ReuseAddr`, `DisableUDPFragment`, `bind_windows.go`); документация: docs/configuration/shared/listen.md, docs/configuration/inbound/index.md.

## Пользователи по протоколам

У большинства серверных входящих поле `users` — массив объектов. `name` нигде не обязателен: он попадает в логи и в метаданные (условие `auth_user` правил).

| Тип | Поля объекта пользователя | Пустой список |
|---|---|---|
| `mixed`, `socks`, `http` | `username` (string), `password` (string) | Без аутентификации. |
| `naive` | `username`, `password` | Ошибка создания `missing users` (проверено). |
| `shadowsocks` | `name` (string), `password` (string) | Однопользовательский режим с общим `password`. |
| `vmess` | `name`, `uuid` (string), `alterId` (int) — именно `alterId`, не `alter_id` (`alter_id` — ошибка разбора, проверено) | check пропускает; подключиться никто не сможет. |
| `trojan` | `name`, `password` | То же. |
| `vless` | `name`, `uuid`, `flow` (string) | То же. |
| `hysteria` | `name`, `auth` (string в base64 — пароль в байтах), `auth_str` (string) | То же. |
| `hysteria2` | `name`, `password` | То же. |
| `tuic` | `name`, `uuid` (обязателен, корректный UUID), `password` | То же. |
| `shadowtls` | `name`, `password` | Для версии 3 — ошибка `missing users` (проверено). |
| `anytls` | `name`, `password` | check пропускает; подключиться никто не сможет. |
| `snell` | `name`, `userkey` (string) | Однопользовательский режим с ключом `psk`. |

Замечания:

- vmess и vless принимают в `uuid` любую строку: если она не разбирается как UUID, используется UUIDv5 от этой строки с нулевым пространством имён (совместимо с Xray). Поэтому `"uuid": "bad"` проходит check (проверено). У tuic так нельзя: `invalid uuid for user 0` (проверено).
- У hysteria при заполненных обоих полях используется `auth_str`. Некорректный base64 в `auth` — ошибка разбора (проверено).
- У `mixed`, `socks`, `http` отсутствующий пароль допустим (пустая строка).

Исходники: option/simple.go, option/naive.go, option/shadowsocks.go, option/vmess.go, option/trojan.go, option/vless.go, option/hysteria.go, option/hysteria2.go, option/tuic.go, option/shadowtls.go, option/anytls.go, option/snell.go; библиотеки sing (common/auth), sing-vmess (vless/service.go, service.go), sing-quic.

## TLS у входящих

Объект `tls` у входящих — серверная форма, её поля описаны в [shared.md](shared.md#входящий-tls-сервер) (сертификат и ключ или `certificate_provider`, `insecure` для самоподписанного сертификата на лету, ECH, Reality, проверка клиентских сертификатов). Файлы сертификатов читаются при создании, поэтому отсутствующий файл ловит check.

| Тип | Поле `tls` | Требование |
|---|---|---|
| `http`, `mixed` | есть | Необязателен; у `mixed` TLS оборачивает и SOCKS, и HTTP (в документации mixed поле не описано). |
| `vmess`, `vless` | есть | Необязателен. |
| `trojan` | есть | Необязателен, но `fallback_for_alpn` без TLS — ошибка `fallback for ALPN is not supported without TLS` (проверено). |
| `anytls` | есть | Необязателен (используется при `enabled: true`). |
| `naive` | есть | Обязателен, если в `network` есть `udp` (по умолчанию есть): `TLS is required for QUIC server` (проверено). |
| `hysteria`, `hysteria2`, `tuic` | есть | Обязателен и должен быть `enabled`: `TLS required` (проверено). |
| прочие | нет | `shadowtls` проводит рукопожатие с настоящим TLS-сервером (`handshake`), своего сертификата у него нет. |

Reality применим только к TCP-протоколам; поверх QUIC — см. [TLS поверх QUIC](shared.md#tls-поверх-quic). `multiplex.brutal` у входящих на Windows — ошибка check `TCP Brutal is only supported on Linux` (проверено на vmess).

Исходники: option/tls.go (`InboundTLSOptions`), common/tls/server.go, common/tls/std_server.go, protocol/*/inbound.go.

## direct

Принимает TCP и/или UDP и отправляет трафик в маршрутизацию с адресом назначения, равным адресу, на который пришло соединение, либо подменённым. Используется как проброс порта (например, UDP 53 на DNS-сервер через прокси).

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| listen-поля | | | См. [listen](shared.md#поля-прослушивания-listen); `udp_fragment` по умолчанию `true`. |
| `network` | string\|[string] | `tcp` и `udp` | Какие сокеты открыть: `tcp`, `udp`. Другое значение — ошибка разбора `unknown network` (проверено). |
| `override_address` | string | — | Подменить адрес назначения (IP или домен). |
| `override_port` | int | `0` | Подменить порт назначения. Можно задать только порт — адрес останется исходным (проверено: check проходит). |

Исходники: option/direct.go (`DirectInboundOptions`), protocol/direct/inbound.go; документация: docs/configuration/inbound/direct.md.

## mixed

SOCKS4, SOCKS4a, SOCKS5 и HTTP-прокси на одном TCP-порту; протокол определяется по первому байту. UDP — через SOCKS5 UDP ASSOCIATE. Это типичный локальный прокси клиента.

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| listen-поля | | | См. [listen](shared.md#поля-прослушивания-listen). |
| `users` | [object] | — | Пользователи SOCKS и HTTP (`username`, `password`); пусто — без аутентификации. |
| `set_system_proxy` | bool | `false` | Выставить системный прокси при старте и снять при остановке. Linux, Android, Windows, macOS. Поведение на Windows — ниже. |
| `tls` | object | — | Не описано в документации mixed, но есть в коде: серверный TLS для всего порта ([TLS](#tls-у-входящих)). |
| `domain_resolver` | string \| object -> dns server | — | Есть в коде и в schema.json, в документации нет; в 1.14.2 код его не использует (молча, проверено: несуществующий тег проходит check). |

`set_system_proxy` на Windows (по коду):

- Ставится прокси WinINet текущего пользователя процесса (настройки «LAN»): `http://<адрес>:<порт>`, где адрес — `listen`, а при `0.0.0.0`/`::`/отсутствии — `127.0.0.1`. SOCKS в системный прокси не прописывается даже у `mixed`. Список исключений не задаётся.
- При штатной остановке sing-box выставляет «без прокси + автоопределение параметров»; прежние настройки пользователя (свой прокси, PAC) не восстанавливаются.
- Если процесс sing-box убит (TerminateProcess), прокси остаётся указывать на закрытый порт: программы, которые его используют, теряют сеть до ручного исправления.

Исходники: option/simple.go (`HTTPMixedInboundOptions`), protocol/mixed/inbound.go, common/listener/listener.go, common/settings/proxy_windows.go; библиотека sing: common/wininet; документация: docs/configuration/inbound/mixed.md.

## socks

SOCKS4, SOCKS4a и SOCKS5 (включая UDP ASSOCIATE). Поля `set_system_proxy` нет: `unknown field` (проверено).

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| listen-поля | | | См. [listen](shared.md#поля-прослушивания-listen). |
| `users` | [object] | — | `username`, `password`; пусто — без аутентификации. |
| `domain_resolver` | string \| object -> dns server | — | Как у mixed: в документации нет, в коде не используется. |

Исходники: option/simple.go (`SocksInboundOptions`), protocol/socks/inbound.go; документация: docs/configuration/inbound/socks.md.

## http

HTTP-прокси: метод CONNECT и обычные HTTP-запросы. Поля те же, что у [mixed](#mixed): listen-поля, `users` (HTTP Basic), `tls`, `set_system_proxy` (на Windows ведёт себя так же), `domain_resolver` (в коде не используется).

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| listen-поля | | | См. [listen](shared.md#поля-прослушивания-listen). |
| `users` | [object] | — | `username`, `password`; пусто — без аутентификации. |
| `tls` | object | — | Серверный TLS (HTTPS-прокси). |
| `set_system_proxy` | bool | `false` | Как у mixed. |
| `domain_resolver` | string \| object | — | Не документировано, не используется. |

Исходники: option/simple.go (`HTTPMixedInboundOptions`), protocol/http/inbound.go; документация: docs/configuration/inbound/http.md.

## shadowsocks

Сервер Shadowsocks в одном из трёх режимов, который выбирается по заполненным полям: один ключ (нет `users` и `destinations`), много пользователей (`users` или `managed`), реле (`destinations`).

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| listen-поля | | | См. [listen](shared.md#поля-прослушивания-listen). |
| `network` | string\|[string] | `tcp` и `udp` | Какие сокеты открыть. |
| `method` | string | — (обязательно) | `none`, `aes-128-gcm`, `aes-192-gcm`, `aes-256-gcm`, `chacha20-ietf-poly1305`, `xchacha20-ietf-poly1305`, `2022-blake3-aes-128-gcm`, `2022-blake3-aes-256-gcm`, `2022-blake3-chacha20-poly1305`. Потоковых шифров (как у исходящего) на сервере нет. Иное или пустое — ошибка создания `unsupported method` (проверено). |
| `password` | string | — | Для AEAD-методов — любая строка; без неё ошибка `missing password` (проверено). Для методов 2022 — ключ в base64 длиной 16 байт (`2022-blake3-aes-128-gcm`) или 32 байта (остальные два), сгенерировать: `sing-box generate rand --base64 16`; неверный base64 — `decode psk` (проверено). В многопользовательском режиме 2022 это ключ сервера, в многопользовательском AEAD не используется. |
| `users` | [object] | — | `name`, `password`: многопользовательский режим. Поддерживается для AEAD и 2022, не для `none` (`unsupported method: none`, проверено). Для 2022 пароли пользователей — base64-ключи той же длины. |
| `destinations` | [object] | — | Режим реле (только 2022): `name`, `password` (ключ пользователя), `server`, `server_port` — куда пересылать. Вместе с `users` — ошибка `users and destinations options must not be combined` (проверено). |
| `multiplex` | object | — | Входящий multiplex, см. [shared.md](shared.md#мультиплексирование-multiplex). |
| `managed` | bool | `false` | с 1.12. Пользователями управляет сервис SSM API ([experimental.md](experimental.md#service-ssm-api)). Вместе с `users` или `destinations` — ошибка `users and destinations options are not supported in managed servers`. |

Исходники: option/shadowsocks.go, protocol/shadowsocks/inbound.go, protocol/shadowsocks/inbound_multi.go, protocol/shadowsocks/inbound_relay.go; документация: docs/configuration/inbound/shadowsocks.md.

## vmess

Сервер VMess поверх TCP с необязательными TLS, multiplex и V2Ray-транспортом.

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| listen-поля | | | См. [listen](shared.md#поля-прослушивания-listen). |
| `users` | [object] | — | `name`, `uuid`, `alterId`. Документация называет список обязательным; код принимает пустой. `alterId` 0 — только AEAD-аутентификация; больше 0 — включает устаревшую MD5-аутентификацию (для совместимости; значения больше 1 документация не советует). |
| `tls` | object | — | [TLS](#tls-у-входящих). |
| `multiplex` | object | — | [shared.md](shared.md#мультиплексирование-multiplex). |
| `transport` | object | — | V2Ray-транспорт: `http`, `ws`, `quic`, `grpc`, `httpupgrade` ([shared.md](shared.md#v2ray-транспорты-transport)). |

Исходники: option/vmess.go, protocol/vmess/inbound.go; библиотека sing-vmess; документация: docs/configuration/inbound/vmess.md.

## trojan

Сервер Trojan. Нераспознанные запросы можно отдавать на fallback-сервер.

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| listen-поля | | | См. [listen](shared.md#поля-прослушивания-listen). |
| `users` | [object] | — | `name`, `password`. По документации обязательно, код принимает пустой. |
| `tls` | object | — | [TLS](#tls-у-входящих). |
| `fallback` | object | — | `server` (string), `server_port` (int): куда отдавать соединения, не прошедшие проверку Trojan. Работает и без TLS. Некорректный адрес — ошибка создания `invalid fallback address`. Выключено, если пусты `fallback` и `fallback_for_alpn`. |
| `fallback_for_alpn` | object (ALPN -> {`server`, `server_port`}) | — | Fallback по согласованному ALPN; если таблица не пуста, fallback для ALPN вне таблицы отвергается. Требует TLS. |
| `multiplex` | object | — | [shared.md](shared.md#мультиплексирование-multiplex). |
| `transport` | object | — | [shared.md](shared.md#v2ray-транспорты-transport). |

Исходники: option/trojan.go, protocol/trojan/inbound.go; документация: docs/configuration/inbound/trojan.md.

## vless

Сервер VLESS.

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| listen-поля | | | См. [listen](shared.md#поля-прослушивания-listen). |
| `users` | [object] | — | `name`, `uuid` (обязателен), `flow`. По документации список обязателен, код принимает пустой. |
| `users[].flow` | string | `""` | Подпротокол: `""` или `xtls-rprx-vision`. Значение не проверяется при создании (`"bad"` проходит check, проверено); при подключении flow клиента обязан совпасть с flow пользователя, иначе `flow mismatch`. С `xtls-rprx-vision` обычные UDP-запросы отвергаются (`flow does not support UDP`). |
| `tls` | object | — | [TLS](#tls-у-входящих); Reality — здесь. |
| `multiplex` | object | — | [shared.md](shared.md#мультиплексирование-multiplex). |
| `transport` | object | — | [shared.md](shared.md#v2ray-транспорты-transport). |

Исходники: option/vless.go, protocol/vless/inbound.go; библиотека sing-vmess (vless/service.go); документация: docs/configuration/inbound/vless.md.

## naive

Сервер NaiveProxy: принимает HTTP CONNECT с набивкой по HTTP/2 (TCP) и HTTP/3 (UDP). Без TLS по TCP работает как h2c.

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| listen-поля | | | См. [listen](shared.md#поля-прослушивания-listen). |
| `network` | string\|[string] | `tcp` и `udp` | `tcp` — HTTP/2, `udp` — HTTP/3. Если заданы обе сети и HTTP/3 поднять не удалось, выводится предупреждение `naive http3 disabled`, TCP продолжает работать; при одной `udp` это ошибка старта. |
| `users` | [object] | — (обязательно) | `username`, `password`. Пусто — ошибка `missing users` (проверено). |
| `quic_congestion_control` | string | `bbr` | с 1.13. Алгоритм для HTTP/3: `bbr`, `cubic`, `reno`. Проверяется только при старте HTTP/3 (`unknown quic congestion control`); check пропускает любое значение (проверено). |
| `tls` | object | — | [TLS](#tls-у-входящих). Обязателен, если в `network` есть `udp`. |

Исходники: option/naive.go, protocol/naive/inbound.go, protocol/naive/quic/inbound_init.go; документация: docs/configuration/inbound/naive.md.

## hysteria

Сервер Hysteria v1 поверх QUIC.

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| listen-поля | | | См. [listen](shared.md#поля-прослушивания-listen); `udp_fragment` по умолчанию `true`. |
| `up` | string \| int | — | Скорость отдачи. Строка «число единица»: единицы сети чувствительны к регистру — `Bps`, `Kbps`, `KBps`, `Mbps`, `MBps`, `Gbps`, `GBps`, `Tbps`, `TBps` (b — биты, B — байты). Единица `bps` из документации отвергается (`unsupported unit: bps`, проверено), `mbps` строчными тоже. Если сетевая единица не подошла, принимаются байтовые без учёта регистра (`"100 MB"`, `"10k"`) — как байты в секунду: `k`, `M`, `G`… с основанием 1000, `Ki`, `Mi`… с основанием 1024; поэтому `"100 Mb"` — 100 мегабайт/с, а не мегабит (тип `NetworkBytesCompat` библиотеки sing). Число без единицы — байты в секунду (проверено: `"up": 100` проходит). |
| `up_mbps` | int | — | Скорость отдачи в Мбит/с; используется, если `up` не задан или 0. |
| `down` | string \| int | — | Скорость приёма, формат как у `up`. |
| `down_mbps` | int | — | Скорость приёма в Мбит/с. |
| `obfs` | string | — | Пароль обфускации (xplus). |
| `users` | [object] | — | `name`, `auth` (base64), `auth_str`. |
| `tls` | object | — (обязательно) | [TLS](#tls-у-входящих). |
| QUIC-поля | | | [QUIC-поля](shared.md#параметры-quic-quic-fields). Умолчания v1: окно потока 8 МБ, окно соединения 20 МБ, простой 30s, keep-alive 10s. |
| `recv_window_conn` | int (байты) | — | Устарело в 1.14 (удаление по changelog — в 1.16, предупреждения нет). По коду подставляется в `connection_receive_window`, если то не задано. |
| `recv_window_client` | int (байты) | — | То же; по коду подставляется в `stream_receive_window`. |
| `max_conn_client` | int | — | То же; подставляется в `max_concurrent_streams`. |
| `disable_mtu_discovery` | bool | `false` | То же; подставляется в `disable_path_mtu_discovery`. |

Скорость отдачи и приёма обязательна: без них ошибка создания `missing upload speed configuration` / `missing download speed configuration` (проверено).

Исходники: option/hysteria.go, protocol/hysteria/inbound.go, protocol/hysteria/quic.go; библиотеки sing (common/byteformats), sing-quic (hysteria); документация: docs/configuration/inbound/hysteria.md.

## hysteria2

Сервер Hysteria2 поверх QUIC.

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| listen-поля | | | См. [listen](shared.md#поля-прослушивания-listen); `udp_fragment` по умолчанию `true`. |
| `up_mbps` | int | `0` (без ограничения) | Максимальная скорость отдачи, Мбит/с. |
| `down_mbps` | int | `0` (без ограничения) | Максимальная скорость приёма, Мбит/с. |
| `obfs` | object | — | Обфускация QUIC, см. ниже. |
| `users` | [object] | — | `name`, `password`. Режима userpass официального сервера нет: пароль надо писать как `имя:пароль`. |
| `ignore_client_bandwidth` | bool | `false` | Без `up_mbps`/`down_mbps` — велеть клиентам использовать BBR вместо Hysteria CC; с ними — запретить клиентам BBR. Документация называет его несовместимым с `up_mbps`/`down_mbps`, но check сочетание не отвергает (проверено). Поведение изменено в 1.11. |
| `tls` | object | — (обязательно) | [TLS](#tls-у-входящих). |
| QUIC-поля | | | [QUIC-поля](shared.md#параметры-quic-quic-fields). |
| `masquerade` | string \| object | — | Что отвечать как HTTP/3-сервер, если аутентификация не прошла; без него — 404. Изменено в 1.11. См. ниже. |
| `bbr_profile` | string | `standard` | с 1.14. `conservative`, `standard`, `aggressive`; иное — ошибка создания `unsupported BBR profile` (проверено). |
| `brutal_debug` | bool | `false` | Отладочный журнал Hysteria Brutal CC. |
| `realm` | object | — | с 1.14. Регистрация на сервисе Hysteria Realm для обхода NAT, см. ниже. |

`obfs`:

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `type` | string | — | `salamander` или `gecko` (с 1.14). Пустое или иное — ошибка разбора `unknown obfs type` (проверено). |
| `password` | string | — | Обязателен: без него ошибка создания `missing obfs password` (проверено). |
| `min_packet_size` | int | `512` | с 1.14, только `gecko`. Минимальный размер пакета в сети, байт. |
| `max_packet_size` | int | `1200` | с 1.14, только `gecko`. Максимум; должно быть 0 < min ≤ max ≤ 2048, иначе `gecko: invalid packet size range` (проверено). У `salamander` оба поля молча отбрасываются. |

`masquerade` строкой: URL `file:///каталог` (файловый сервер) или `http://…`/`https://…` (обратный прокси); другая схема — ошибка разбора (проверено для `ftp`). Объектом — по полю `type`:

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `type` | string | — | `file`, `proxy`, `string`; иное — ошибка разбора. |
| `directory` | string | — | `file`: корневой каталог. Переменные окружения раскрываются, относительный путь — от рабочего каталога. Отсутствующий каталог не ошибка (check проходит). |
| `url` | string | — | `proxy`: адрес, куда проксировать. |
| `rewrite_host` | bool | `false` | `proxy`: ставить `Host` из `url`; иначе остаётся исходный. |
| `status_code` | int | `200` | `string`: код ответа. |
| `headers` | object (string -> string\|[string]) | — | `string`: заголовки ответа. |
| `content` | string | — | `string`: тело ответа. |

`realm` (с 1.14):

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `server_url` | string | — (обязательно) | URL сервиса Realm; без него `control server URL is required` (проверено). |
| `token` | string | — | Bearer-токен; должен совпасть с одним из `users[].token` сервиса. |
| `realm_id` | string | — (обязательно) | Имя слота: 1–64 символа по `^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`; клиенты указывают то же. Отсутствие — ошибка создания `realm ID is required`, а формат check не проверяет (проверено оба). |
| `stun_servers` | string\|[string] | — (обязательно) | STUN-серверы `host` или `host:port` для определения внешних адресов; пусто — `at least one STUN server is required` (проверено). |
| `stun_domain_resolver` | string \| object -> dns server | правило домена по умолчанию | Каким DNS-сервером разрешать домены STUN (формат как у `domain_resolver`, [shared.md](shared.md#domain_resolver)). Несуществующий тег — ошибка check (проверено). |
| `ip_version` | int | `0` (оба) | `4` или `6`: ограничить Realm, STUN и итоговый QUIC одним семейством; другое — `invalid IP version` (проверено для `5`). Несовместимый `listen` — ошибка создания (`realm.ip_version 6 conflicts with listen address 0.0.0.0`, проверено). |
| `port_mapping` | object | — | Проброс UDP-порта на шлюзе через UPnP или NAT-PMP; ошибки проброса не фатальны. Только IPv4: с `ip_version: 6` — `port mapping requires IPv4` (проверено). |
| `port_mapping.enabled` | bool | `false` | Включить. |
| `port_mapping.timeout` | duration | `10s` | Тайм-аут поиска шлюза и операций. |
| `port_mapping.lifetime` | duration | `10m` | Срок аренды; продлевается на половине срока. |
| `http_client` | string -> http_client \| object | встроенный клиент с умолчаниями (прямое соединение) | Клиент для обращений к Realm ([config.md](config.md#http_clients)). Без поля создаётся свой клиент с пустыми настройками, то есть без `detour`, напрямую; `route.default_http_client` здесь не используется. Несуществующий тег — ошибка check `http_client not found` (проверено). |

Исходники: option/hysteria2.go, protocol/hysteria2/inbound.go; библиотека sing-quic (hysteria2, congestion_meta2); документация: docs/configuration/inbound/hysteria2.md.

## tuic

Сервер TUIC v5 поверх QUIC.

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| listen-поля | | | См. [listen](shared.md#поля-прослушивания-listen); `udp_fragment` по умолчанию `true`. |
| `users` | [object] | — | `name`, `uuid` (обязателен, корректный UUID: `missing uuid for user 0`, `invalid uuid for user 0`, проверено), `password`. |
| `congestion_control` | string | `cubic` | `cubic`, `new_reno`, `bbr`; иное — ошибка создания `unknown congestion control algorithm` (проверено). |
| `auth_timeout` | duration | `3s` | Сколько ждать команду аутентификации от клиента. |
| `zero_rtt_handshake` | bool | `false` | Разрешить 0-RTT; уязвимо к повтору пакетов, документация советует не включать. |
| `heartbeat` | duration | `10s` | Интервал heartbeat для поддержания соединения. |
| `tls` | object | — (обязательно) | [TLS](#tls-у-входящих). |
| QUIC-поля | | | [QUIC-поля](shared.md#параметры-quic-quic-fields). |

Исходники: option/tuic.go, protocol/tuic/inbound.go; библиотека sing-quic (tuic/service.go); документация: docs/configuration/inbound/tuic.md.

## QUIC-поля (hysteria, hysteria2, tuic)

с 1.14. Общий набор полей QUIC-протоколов, пишется в объект входящего плоско: `idle_timeout` (duration), `keep_alive_period` (duration), `stream_receive_window` (size), `connection_receive_window` (size), `max_concurrent_streams` (int; у входящего — предел одновременных входящих потоков), `initial_packet_size` (int), `disable_path_mtu_discovery` (bool, `false`). Таблица и смысл полей — в [shared.md](shared.md#параметры-quic-quic-fields). Незаданное или нулевое значение означает умолчание протокола (для hysteria v1 оно указано в её таблице выше), `initial_packet_size` по умолчанию берётся из quic-go.

Исходники: option/http.go (`QUICOptions`, `HTTP2Options`), protocol/hysteria/quic.go; документация: docs/configuration/shared/quic.md, docs/configuration/shared/http2.md.

## shadowtls

ShadowTLS: проводит настоящее TLS-рукопожатие с чужим сервером (`handshake`), а затем передаёт поток дальше — обычно через `detour` во входящий shadowsocks на `127.0.0.1`.

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| listen-поля | | | См. [listen](shared.md#поля-прослушивания-listen); `detour` здесь основной способ использования. |
| `version` | int | `1` | Версия протокола: `1`, `2`, `3`; другое — ошибка создания `unknown protocol version` (проверено для `4`). |
| `password` | string | — | Пароль, только версия 2. Отсутствие check не отвергает (проверено). |
| `users` | [object] | — | `name`, `password`; только версия 3, там обязателен (`missing users`, проверено). |
| `handshake` | object | — | Сервер рукопожатия: `server`, `server_port` и dial-поля ([shared.md](shared.md#поля-подключения-dial)). Обязателен, кроме `wildcard_sni: all`: иначе `missing default handshake information` (проверено). Несуществующий `detour` в нём check пропускает (проверено). |
| `handshake_for_server_name` | object (SNI -> объект как `handshake`) | — | Свой сервер рукопожатия для конкретного SNI; версии 2 и 3. |
| `strict_mode` | bool | `false` | Строгий режим; только версия 3. |
| `wildcard_sni` | string | `off` | с 1.12, только версия 3. `off`; `authed` — у аутентифицированных соединений адрес назначения заменяется на `<SNI>:443`; `all` — у всех соединений. SNI из `handshake_for_server_name` не затрагиваются. Иное значение — ошибка разбора. |

Исходники: option/shadowtls.go, protocol/shadowtls/inbound.go; библиотека sing-shadowtls; документация: docs/configuration/inbound/shadowtls.md.

## anytls

с 1.12. Сервер AnyTLS.

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| listen-поля | | | См. [listen](shared.md#поля-прослушивания-listen). |
| `users` | [object] | — | `name`, `password`. По документации обязательно, код принимает пустой. |
| `padding_scheme` | string\|[string] | схема по умолчанию | Строки схемы набивки. По умолчанию: `stop=8`, `0=30-30`, `1=100-400`, `2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000`, `3=9-9,500-1000`, `4=500-1000`, `5=500-1000`, `6=500-1000`, `7=500-1000`. Неверный формат — ошибка создания `incorrect padding scheme format` (проверено). |
| `tls` | object | — | [TLS](#tls-у-входящих). |

Исходники: option/anytls.go, protocol/anytls/inbound.go; библиотека sing-anytls; документация: docs/configuration/inbound/anytls.md.

## snell

с 1.14. Сервер Snell версии 5 или 6 (реализация sing-snell, без QUIC-режима v5). Набор полей зависит от `version`: поле другой версии — ошибка разбора (`mode` при `version: 5` — `unknown field "mode"`, проверено).

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| listen-поля | | | См. [listen](shared.md#поля-прослушивания-listen). |
| `version` | int | — (обязательно) | `5` или `6`. Отсутствие — `snell: missing version`, другое — `snell: unsupported version` (ошибки разбора, проверено для `4`). |
| `psk` | string | — (обязательно) | Ключ сервера. Пусто — `snell: missing pre-shared key`; для v6 длина 12–255 байт (`psk length must be between 12 and 255 bytes`, проверено). |
| `users` | [object] | — | `name`, `userkey`: многопользовательский режим; `psk` остаётся ключом сервера. |
| `obfs_mode` | string | `none` | Только v5. Документация: `none`, `http`. Код принимает также `tls`, регистр не важен (проверено); иное — ошибка создания `snell: unknown obfs mode`. |
| `mode` | string | `default` | Только v6. Формирование трафика: `default`, `unshaped`, `unsafe-raw`; иное — `snell: unknown v6 mode`. |

Исходники: option/snell.go, protocol/snell/inbound.go; библиотека sing-snell (obfs.go, snellv6/mode.go); документация: docs/configuration/inbound/snell.md.

## redirect

Прозрачный TCP-прокси для трафика, перенаправленного `iptables`/`nftables` (`REDIRECT`) или `pf`: исходный адрес назначения берётся из сокета. Только Linux и macOS. Полей, кроме [listen-полей](shared.md#поля-прослушивания-listen), нет.

На Windows (по коду) check и старт проходят (проверено: check), слушатель открывается, но каждое соединение завершается ошибкой `get redirect destination`.

Исходники: option/redir.go (`RedirectInboundOptions`), protocol/redirect/redirect.go, common/redir; документация: docs/configuration/inbound/redirect.md.

## tproxy

Прозрачный прокси TPROXY для TCP и UDP. Только Linux.

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| listen-поля | | | См. [listen](shared.md#поля-прослушивания-listen). |
| `network` | string\|[string] | `tcp` и `udp` | Какие сокеты открыть. |
| `udp_mapping` | string | `endpoint_independent` | с 1.14. [UDP NAT](shared.md#udp-nat). |
| `udp_filtering` | string | `endpoint_independent` | с 1.14. [UDP NAT](shared.md#udp-nat). |
| `udp_nat_max` | int | `0` (авто) | с 1.14. [UDP NAT](shared.md#udp-nat). |

На Windows check проходит (проверено), по коду открытие сокета с опцией TPROXY завершается ошибкой, то есть ошибка при старте.

Исходники: option/redir.go (`TProxyInboundOptions`), protocol/redirect/tproxy.go, common/redir/tproxy_other.go; документация: docs/configuration/inbound/tproxy.md, docs/configuration/shared/udp-nat.md.

## cloudflared

с 1.14. Встроенный клиент Cloudflare Tunnel: sing-box сам подключается к Cloudflare, а трафик туннеля (TCP, UDP, ICMP) идёт в маршрутизацию с этим входящим в метаданных. Listen-полей нет (`listen_port` — `unknown field`, проверено).

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `token` | string | — (обязательно) | Токен туннеля (base64) из панели Zero Trust. Разбирается при создании: неверный — ошибка check (`parse token: …`, проверено). |
| `ha_connections` | int | `4` | Число соединений с edge; ограничено числом найденных адресов. |
| `protocol` | string | авто | Документация: `quic`, `http2`. Код принимает `""`/`auto` (автовыбор), `quic`, `http2`, `h2mux` (заменяется на `http2` с предупреждением); иное — `unsupported protocol` (проверено). |
| `post_quantum` | bool | `false` | Постквантовый обмен ключами на управляющем соединении. |
| `edge_ip_version` | int | `0` (авто) | `0`, `4`, `6`; иное — ошибка создания (проверено). |
| `datagram_version` | string | `v2` (или то, что задаёт аккаунт) | `v2` или `v3`; имеет смысл только с QUIC. Иное — ошибка создания (проверено). |
| `grace_period` | duration | `30s` | Окно штатного завершения соединений при остановке. |
| `region` | string | — | Регион edge. Несовместимо с endpoint, зашитым в токен (ошибка создания). |
| `control_dialer` | object | — | Dial-поля для управляющего канала ([shared.md](shared.md#поля-подключения-dial)). Несуществующий `detour` check пропускает (проверено). |
| `tunnel_dialer` | object | — | Dial-поля для канала данных. |

Исходники: option/cloudflared.go, protocol/cloudflare/inbound.go, include/cloudflared.go; библиотека sing-cloudflared (service.go, internal/transport/protocol_selector.go); документация: docs/configuration/inbound/cloudflared.md.

## tun

Виртуальный сетевой адаптер: система отправляет в него IP-пакеты, sing-box превращает их в TCP/UDP-соединения (стек `system`, `gvisor` или `mixed`) и отдаёт в маршрутизацию. Поддерживается на Linux, Windows и macOS; на Android и iOS — через графические клиенты. Listen-полей у `tun` нет; `udp_timeout` и `netns` — собственные поля.

### Поля tun

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `interface_name` | string | `tunN` | Имя адаптера. Пусто — `tun` плюс номер на единицу больше наибольшего среди существующих интерфейсов `tun<число>` (дыры в нумерации не заполняются; нет таких — `tun0`); на macOS — `utunN`. |
| `netns` | string -> network_namespace | — | с 1.14, только Linux. Создать адаптер в сетевом пространстве имён (имя, путь или тег); `auto_route`/`auto_redirect` работают внутри него. По документации несовместимо с `platform`. На Windows — ошибка check `` `netns` is only supported on Linux `` (проверено). |
| `mtu` | int | `65535` | MTU адаптера. Умолчание на Android — `9000`, в Apple Network Extension — `4064`. Строка — ошибка разбора (проверено). |
| `address` | prefix\|[prefix] | — | с 1.10. IPv4- и IPv6-префиксы адаптера, например `172.19.0.1/30`, `fdfe:dcba:9876::1/126`. Фактически обязателен: см. [адреса и стек](#адреса-mtu-и-стек). |
| `dns_mode` | string | `hijack` | с 1.14. `disabled`, `native`, `hijack`, см. [DNS](#dns-dns_mode-и-dns_address). Неизвестное значение не отвергается и ведёт себя как `native` (по коду; check проходит, проверено). |
| `dns_address` | ip\|[ip] | производный | с 1.14. DNS-серверы, которые прописываются адаптеру. |
| `auto_route` | bool | `false` | Направить маршрут по умолчанию (или `route_address`) в адаптер. Для защиты от петли нужен `route.auto_detect_interface`, `route.default_interface` или `bind_interface` у исходящих ([route.md](route.md)). |
| `iproute2_table_index` | int | `2022` | с 1.10, Linux. Номер таблицы маршрутов `auto_route`. |
| `iproute2_rule_index` | int | `9000` | с 1.10, Linux. Начальный номер правил `ip rule`. |
| `auto_redirect` | bool | `false` | с 1.10, только Linux, требует `auto_route`. Перехват через nftables, см. [auto_redirect](#auto_redirect-linux). |
| `auto_redirect_input_mark` | mark | `0x2023` | с 1.10, Linux. Метка входящих соединений `auto_redirect`. |
| `auto_redirect_output_mark` | mark | `0x2024` | с 1.10, Linux. Метка исходящих соединений. |
| `auto_redirect_reset_mark` | mark | `0x2025` | с 1.13, Linux. Метка сброса для pre-match. |
| `auto_redirect_nfqueue` | int (0–65535) | `100` | с 1.13, Linux. Номер NFQueue для pre-match. |
| `auto_redirect_iproute2_fallback_rule_index` | int | `32768` | с 1.12.18 (по документации), Linux. Правило-запасной путь после системных (`32766` main, `32767` default): в таблицу sing-box идёт только то, для чего в системных таблицах маршрута нет. |
| `exclude_mptcp` | bool | `false` | с 1.13, Linux с nftables, `auto_route` и `auto_redirect`. MPTCP прозрачно не проксируется: при `true` такие соединения идут напрямую, иначе отвергаются. |
| `loopback_address` | ip\|[ip] | — | с 1.12. TCP-соединения на эти адреса замыкаются на адрес источника (приём как у SideStore/StosVPN с `10.7.0.1`); с `auto_redirect` — и для устройств LAN. Реализовано в стеке, работает и на Windows. |
| `strict_route` | bool | `false` | Строгая маршрутизация при `auto_route`; действие зависит от ОС, см. [auto_route и strict_route](#auto_route-strict_route-и-маршруты). Изменено в 1.13.3. |
| `route_address` | prefix\|[prefix] | — | с 1.10. Какие сети направлять в адаптер вместо маршрута по умолчанию (при `auto_route`). |
| `route_exclude_address` | prefix\|[prefix] | — | с 1.10. Какие сети исключить из маршрутов адаптера. |
| `route_address_set` | string\|[string] -> rule-set | — | с 1.10 (с `auto_redirect`), с 1.11 (без него). IP-CIDR из rule-set: с `auto_redirect` — в правила nftables, без него — добавляются к `route_address`. Несуществующий тег — ошибка check `parse route_address_set: rule-set not found` (проверено). В графическом клиенте Android не работает. |
| `route_exclude_address_set` | string\|[string] -> rule-set | — | То же для исключений (`route_exclude_address`). |
| `include_interface` | string\|[string] | — | Linux с `auto_route`: ограничить перехват этими входящими интерфейсами. Несовместимо с `exclude_interface`. |
| `exclude_interface` | string\|[string] | — | Linux: исключить интерфейсы. При `strict_route` обратный трафик к ним не исключается сам: их тоже нужно указать (например `br-lan`, `pppoe-wan`). |
| `include_uid` | int\|[int] | — | Linux с `auto_route`: перехватывать только этих пользователей. |
| `include_uid_range` | string\|[string] | — | То же диапазонами `"начало:конец"`; формат проверяется при создании на любой ОС (`missing ':' in range`, проверено). |
| `exclude_uid` | int\|[int] | — | Исключить пользователей. |
| `exclude_uid_range` | string\|[string] | — | Исключить диапазоны. |
| `include_android_user` | int\|[int] | — | Android с `auto_route`: пользователи Android (`0` — основной, `10` — рабочий профиль). |
| `include_package` | string\|[string] | — | Android: только эти пакеты. |
| `exclude_package` | string\|[string] | — | Android: исключить пакеты. |
| `include_mac_address` | string\|[string] | — | с 1.14, Linux с `auto_route` и `auto_redirect`: только эти MAC-адреса. Несовместимо с `exclude_mac_address`. Формат проверяется на любой ОС (`invalid MAC address`, проверено). |
| `exclude_mac_address` | string\|[string] | — | с 1.14. Исключить MAC-адреса. |
| `udp_timeout` | duration \| int | `5m` | Время жизни UDP-сессии; целое — секунды (проверено). В стеке `system` тем же сроком ограничена и таблица TCP-трансляций. |
| `udp_mapping` | string | `endpoint_independent` | с 1.14. [UDP NAT](shared.md#udp-nat); неизвестное значение — ошибка разбора (проверено). |
| `udp_filtering` | string | `endpoint_independent` | с 1.14. [UDP NAT](shared.md#udp-nat). |
| `udp_nat_max` | int | `0` (авто) | с 1.14. Предел UDP-сессий, [UDP NAT](shared.md#udp-nat). |
| `stack` | string | `mixed` (в сборках с gVisor), иначе `system` | Стек L3 -> L4: `system`, `gvisor`, `mixed` (TCP через `system`, UDP через gVisor). Исключение из умолчания — Apple Network Extension с включением всех сетей: там `gvisor`. Ветка sing-tun «при GSO — `system`» для пустого `stack` недостижима: sing-box включает GSO только на Linux и только при явном `stack: gvisor` (и MTU меньше 49152). На Windows умолчание — `mixed`. Неизвестное значение — ошибка только при старте (`unknown stack`), check проходит (проверено). |
| `platform` | object | — | Настройки для графических клиентов, см. [platform](#platform). |

### Адреса, MTU и стек

- `address` не имеет умолчания. Стеки `system` и `mixed` требуют, чтобы в первом префиксе каждого семейства был ещё один адрес после адреса адаптера: `/32` даёт при старте `need one more IPv4 address in first prefix for system stack`; без адресов вообще — `missing interface address`. check этого не видит (проверено для `/32` и для пустого `address`).
- По коду sing-tun: если у адаптера только IPv4-префикс `/32` без IPv6 и `dns_mode` не `disabled`, вычисление производного DNS-адреса при старте обращается к несуществующему IPv6-префиксу — это паника, а не ошибка (не проверено запуском). Используйте `/30` или задайте `dns_address`.
- Для `address: 172.19.0.1/30` производный DNS-адрес и шлюз маршрутов — `172.19.0.2`.
- `gvisor` и `mixed` требуют сборку с `with_gvisor` (в официальной есть).

### auto_route, strict_route и маршруты

- Без `auto_route` адаптер получает адреса, но маршрутов нет: в него попадает только трафик в его собственные подсети. `strict_route`, `route_address*` и DNS адаптера (на Windows) без `auto_route` не действуют.
- С `auto_route` в адаптер направляются `0.0.0.0/0` и `::/0` либо `route_address` (и IP из `route_address_set`), за вычетом `route_exclude_address` и `route_exclude_address_set`. Маршрут семейства добавляется, только если у адаптера есть адрес этого семейства: без IPv6-адреса IPv6 идёт мимо адаптера (на Windows без `strict_route` это утечка).
- `strict_route` на Linux: неподдерживаемые сети становятся недоступными; ICMP без `strict_route` и `auto_redirect` мимо TUN (исторически); с `auto_redirect` определяет, идёт ли трафик с `SO_BINDTODEVICE` через sing-box.
- `strict_route` на Windows — см. [tun на Windows](#tun-на-windows).
- `route_address_set` без `auto_redirect` (единственный вариант на Windows) читается один раз при старте: обновления rule-set на маршруты не влияют, пока sing-box не перезапущен (обратный вызов регистрируется только при `auto_redirect`). Если в rule-set нет IP-CIDR, пишется предупреждение `no destination IP CIDR rules found in rule-set`.
- Трафик из адаптера до маршрутизации проходит pre-match (правила с действиями `reject`, `bypass` и т. п.), см. [route.md](route.md#pre-match).

### DNS: dns_mode и dns_address

с 1.14. До 1.14 sing-box не трогал DNS адаптера и системный брандмауэр; теперь режим по умолчанию `hijack` делает и то и другое.

| Режим | Что делает |
|---|---|
| `disabled` | DNS адаптеру не прописывается (на Windows — очищается), DNS-трафик не перехватывается. |
| `native` | Адаптеру прописываются DNS-серверы средствами ОС: на Windows и Apple — DNS интерфейса, на Linux — через systemd-resolved. На Windows только при `auto_route`. |
| `hijack` | Как `native`, плюс перехват порта 53. Linux без `auto_redirect` — правило iproute2, из-за которого DNS не уходит в напрямую подключённые подсети мимо TUN (адреса не переписываются); с `auto_redirect` — DNAT порта 53 на `dns_address`. Перехватить DNS к адресам самого хоста (`127.0.0.53`, свой LAN-адрес) на Linux нельзя. Windows со `strict_route` — фильтр WFP блокирует порт 53 через все интерфейсы, кроме TUN. |

`dns_address`:

- Не задан — берётся по одному адресу на семейство: следующий после первого адреса в `address`. В режимах `native` и `hijack` соединения на эти производные адреса сразу уходят в DNS-модуль sing-box (как действие `hijack-dns`) — правило маршрутизации для этого не нужно.
- Задан — эти адреса прописываются адаптеру, но автоматического перехвата нет: нужно правило с действием `hijack-dns` ([route.md](route.md#hijack-dns)).

### Фильтры по интерфейсам, UID, пакетам и MAC

`include_*`/`exclude_*` для интерфейсов и UID работают только на Linux с `auto_route`; для пользователей и пакетов Android — только на Android; MAC-адреса — только на Linux с `auto_redirect`. На Windows все они молча игнорируются (check проходит, проверено), хотя формат диапазонов UID и MAC-адресов проверяется при создании.

### auto_redirect (Linux)

Только Linux (на Android — лишь простой IPv4 TCP из-за отсутствия nftables и ip6tables), требует `auto_route`: без него ошибка check `` `auto_route` is required by `auto_redirect` `` (проверено). Перехватывает TCP через nftables, что быстрее tproxy, устраняет конфликт TUN с мостами Docker и сам добавляет правила совместимости в fw4 OpenWrt. Несовместимо с `route.default_mark` и `routing_mark` в dial-полях. С `auto_redirect` `route_address_set`/`route_exclude_address_set` попадают в наборы nftables и обновляются вместе с rule-set. Переменная окружения `DISABLE_NFTABLES=true` включает запасной путь через iptables.

На Windows `auto_redirect: true` вместе с `auto_route` — ошибка check `initialize auto-redirect: invalid argument` (проверено).

### platform

Параметры, которые применяют графические клиенты через свой платформенный интерфейс. Консольный `sing-box.exe` их не использует, но структуру проверяет: неизвестный ключ — ошибка разбора (проверено).

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `http_proxy` | object | — | Системный HTTP-прокси, выставляемый клиентом. |
| `http_proxy.enabled` | bool | `false` | Включить. |
| `http_proxy.server` | string | — (обязательно) | Адрес прокси. |
| `http_proxy.server_port` | int | — (обязательно) | Порт прокси. |
| `http_proxy.bypass_domain` | string\|[string] | — | Домены в обход прокси; на Apple сопоставляются как суффиксы. |
| `http_proxy.match_domain` | string\|[string] | — | Домены, для которых использовать прокси; только графические клиенты Apple. |

### tun на Windows

По коду sing-tun той же сборки (`tun_windows.go`, `stack_system_windows.go`):

- Нужен процесс с правами администратора (создание адаптера wintun). Библиотека `wintun.dll` встроена в `sing-box.exe` и загружается из памяти — отдельный файл не нужен.
- GUID адаптера вычисляется из имени (MD5 от `"wintun"` и имени): при постоянном `interface_name` Windows видит тот же адаптер (и тот же сетевой профиль) от запуска к запуску. Если адаптер с таким именем уже существует, он открывается повторно. Тип туннеля в системе — `sing-tun`.
- Адреса `address` назначаются адаптеру, MTU — интерфейсу, регистрация адаптера в DNS отключается.
- `auto_route`: автоматическая метрика интерфейса выключается, метрика ставится `0`; маршруты добавляются через шлюз — следующий адрес подсети. После добавления маршрутов и при закрытии адаптера сбрасывается кэш DNS-клиента Windows. DNS адаптера — только при `auto_route` и `dns_mode` не `disabled`.
- `strict_route` работает на Windows 10 и новее (на более старых — предупреждение `strict routing is not supported on Windows versions below 10`, фильтры не ставятся). Создаётся динамическая сессия WFP — фильтры исчезают вместе с процессом sing-box. Фильтры: разрешить всё самому процессу sing-box; если у адаптера нет IPv6-адреса — запретить остальным программам исходящие IPv6-соединения; разрешить всё через адаптер; при `dns_mode: hijack` (умолчание) — запретить соединения на порт 53 через прочие интерфейсы. Других запретов нет: IPv4-сети из `route_exclude_address` по-прежнему доступны мимо адаптера. С `dns_mode: native` блокировки DNS нет, и защита от утечки DNS через другие интерфейсы, которую обещает документация `strict_route`, не действует. Документация предупреждает, что `strict_route` может мешать части программ (например VirtualBox).
- Стеки `system` и `mixed` при каждом старте добавляют (если его ещё нет) постоянное правило брандмауэра Windows с именем `sing-tun (<абсолютный путь к sing-box.exe>)`: разрешить входящий TCP для этого exe во всех профилях. sing-box его не удаляет. Стек `gvisor` правило не создаёт.
- Поля только для Linux и Android (`include_*`/`exclude_*`, `iproute2_*`, `auto_redirect_*`-метки, `exclude_mptcp`) молча игнорируются; `auto_redirect: true` и `netns` — ошибки check.
- Для защиты от петли на Windows нужен `route.auto_detect_interface: true` (адаптер sing-box исключается из выбора интерфейса по умолчанию) или явный интерфейс ([route.md](route.md#платформы-и-windows)).

### Устаревшие и удалённые поля tun

| Поле | Тип | Состояние в 1.14.2 |
|---|---|---|
| `inet4_address`, `inet6_address` | prefix\|[prefix] | Устарели в 1.10, удалены в 1.12: ошибка создания `legacy tun address fields are deprecated in sing-box 1.10.0 and removed in sing-box 1.12.0` (проверено). Замена — `address`. |
| `inet4_route_address`, `inet6_route_address` | prefix\|[prefix] | То же; замена — `route_address`. |
| `inet4_route_exclude_address`, `inet6_route_exclude_address` | prefix\|[prefix] | То же; замена — `route_exclude_address`. |
| `gso` | bool | Устарело в 1.11, удалено в 1.12: `true` — ошибка создания (проверено). |
| `endpoint_independent_nat` | bool | Не действует с 1.11; принимается молча (проверено). С 1.14 поведение NAT задают `udp_mapping`/`udp_filtering`. |
| `sniff`, `sniff_override_destination`, `sniff_timeout`, `domain_strategy`, `udp_disable_domain_unmapping` | как в listen-полях | Удалены в 1.13: ошибка создания (не разбора), проверено для `sniff`. |

Исходники: option/tun.go (`TunInboundOptions`, `FwMark`), option/tun_platform.go, protocol/tun/inbound.go; библиотека sing-tun: tun.go (`Options`, `DNSModeOrDefault`, `Inet4DNSAddress`), tun_rules.go (`BuildAutoRouteRanges`), tun_windows.go, stack.go (`NewStack`), stack_system.go, stack_system_windows.go, redirect_stub.go, internal/wintun; документация: docs/configuration/inbound/tun.md, docs/configuration/shared/udp-nat.md, docs/changelog.md (1.14.0, пункт 19).

## Что ловит check, а что всплывает позже

Проверено на `sing-box.exe` 1.14.2 для Windows, если не оговорено иное.

Ошибка разбора (check, `decode config`):

- неизвестный `type`, неизвестный ключ, `"Type"`/`"Tag"` с заглавной, дубликат тега;
- удалённые listen-поля (`sniff` и др.) у всех типов с listen-полями;
- `listen` не IP-литерал, `listen_port` больше 65535, `network` не `tcp`/`udp`, `udp_timeout` строкой без единицы;
- `udp_mapping`/`udp_filtering` вне списка, схема URL в `masquerade`, тип `obfs` hysteria2, `version` snell и поля чужой версии snell, `wildcard_sni` вне списка, base64 в `users[].auth` hysteria, `address` tun без `/`, `mtu` строкой.

Ошибка создания (check, `initialize inbound[N]`):

- tun: `netns` и `auto_redirect` на Windows, `auto_redirect` без `auto_route`, удалённые поля адресов, `gso: true`, `sniff` и др., несуществующий rule-set в `route_address_set`/`route_exclude_address_set`, неверный MAC или диапазон UID;
- shadowsocks: метод, отсутствующий пароль, base64-ключ 2022, `users` вместе с `destinations`, `managed` вместе с ними;
- TLS: отсутствие TLS у hysteria, hysteria2, tuic и у naive с UDP; отсутствующие файлы сертификатов ([shared.md](shared.md#tls));
- naive без `users`; hysteria без скорости; tuic без или с неверным `uuid`, неизвестный `congestion_control`; hysteria2 без пароля `obfs`, неверные размеры gecko, неизвестный `bbr_profile`, ошибки `realm` (URL, `realm_id`, STUN, `ip_version`, `port_mapping`, теги `http_client` и `stun_domain_resolver`);
- shadowtls: `version` вне 1–3, v3 без `users`, отсутствие `handshake`; anytls с неверным `padding_scheme`; snell без `psk` или с неверной длиной, неизвестный `obfs_mode`; trojan `fallback_for_alpn` без TLS;
- cloudflared: `token`, `protocol`, `datagram_version`, `edge_ip_version`;
- `multiplex.brutal` у входящего на Windows; `shadowsocksr`.

Только при старте (check проходит):

- занятый порт или нет прав на порт; `netns` в listen-полях на Windows (по коду); `proxy_protocol`;
- tproxy на Windows (по коду); tun: неизвестный `stack`, отсутствие `address` или `/32` при стеке `system`/`mixed`, паника при `/32` без IPv6 (по коду); ошибка создания адаптера без прав администратора;
- naive с `network: udp` и неизвестным `quic_congestion_control` (с обеими сетями — только предупреждение).

При подключении: `detour` (нет тега, цель не принимает инъекцию, петля, любой UDP), redirect на Windows, несовпадение `flow` у vless.

Молча (принимается, не действует или не проверяется): `domain_resolver` у socks, http, mixed; `routing_mark` и `tcp_multi_path` вне Linux; Linux- и Android-поля tun на Windows; `platform` в консольном sing-box; `endpoint_independent_nat`; неизвестный `dns_mode`; лишние поля `obfs` salamander; `ignore_client_bandwidth` вместе с `up_mbps`/`down_mbps`; отсутствие `password` у shadowtls v2; формат `realm_id`; не-UUID строки в `uuid` vmess/vless (превращаются в UUIDv5); пустые `users` у vmess, trojan, vless, hysteria, hysteria2, anytls.

## Заметки для tray-sing-box

- Guard проекта (`internal/infrastructure/configfile/guard.go`) пропускает только типы `tun`, `mixed`, `socks`, `http`, `direct` и `listen` на loopback. Отсутствующий `listen` безопасен: sing-box слушает `127.0.0.1`. `"listen": "localhost"` guard пропускает, но sing-box такое значение не принимает (check: `unable to parse IP`) — вреда нет.
- Проба связи (`Editor.LocalProxyURL`) берёт первый `mixed`/`http` (иначе `socks`) по точным ключам `type` и `listen_port` и всегда стучится на `127.0.0.1`. sing-box же принимает `"Listen_Port"` в любом регистре, а `listen` может быть `::1` или другим loopback-адресом; при заданных `users` или включённом `tls` у входящего проба без учётных данных и без TLS не пройдёт. Во всех этих случаях статус «нет связи» будет ложным.
- `set_system_proxy` плохо сочетается с тем, как приложение останавливает sing-box (TerminateProcess): снять прокси WinINet успевает только штатное закрытие, после убийства процесса прокси указывает на закрытый порт. Даже при штатном закрытии прежние настройки прокси пользователя не восстанавливаются.
- Стеки `system` и `mixed` (`mixed` — умолчание) оставляют постоянное правило брандмауэра `sing-tun (<путь к sing-box.exe>)`. Для установленной копии это путь в `Program Files\SingBoxTray`; деинсталлятор его сейчас не удаляет.
- С 1.14 умолчание `dns_mode: hijack` прописывает DNS адаптеру TUN (`172.19.0.2` для `172.19.0.1/30`) и при `strict_route` блокирует порт 53 на остальных интерфейсах. Конфиги, рассчитанные на 1.13, после обновления sing-box ведут себя иначе в части DNS.
- Фильтры WFP `strict_route` принадлежат динамической сессии и исчезают вместе с процессом sing-box — после его убийства сеть не остаётся заблокированной.
- `sing-box format` переписывает ключи пользователей socks/http/mixed в `Username`/`Password`; маскирование секретов в проекте сравнивает свёрнутые ключи и это переживает.

## Расхождения документации и кода

Везде действует код 1.14.2.

1. `listen` помечен в документации обязательным; код без него слушает `127.0.0.1`.
2. Документация tun ссылается на listen-поля; у `TunInboundOptions` их нет, `listen` — ошибка разбора (проверено).
3. У `mixed` есть поле `tls` (код, schema.json), в документации mixed его нет.
4. У `socks`, `http`, `mixed` есть поле `domain_resolver` (код, schema.json), в документации нет, и в 1.14.2 оно ни на что не влияет.
5. Таблица «Injectable» в документации: direct, redirect и tproxy отмечены как не принимающие инъекцию, но по коду у них есть нужный метод, и маршрутизатор примет их как TCP-цель `detour`. UDP-инъекцию не поддерживает ни один входящий.
6. Hysteria v1: документация советует заменить `recv_window_conn` на `stream_receive_window`, а `recv_window_client` на `connection_receive_window`; код подставляет наоборот (`recv_window_conn` -> `connection_receive_window`, `recv_window_client` -> `stream_receive_window`). Документация помечает поля устаревшими в 1.14 без срока, changelog называет удаление в 1.16; предупреждения при запуске нет.
7. Hysteria v1 `up`/`down`: документация перечисляет единицу `bps`, код её отвергает (`unsupported unit: bps`, проверено). Код дополнительно принимает число (байты в секунду) и байтовые единицы без учёта регистра (`"100 MB"`), чего в документации нет.
8. Snell `obfs_mode`: документация — `none`, `http`; код принимает ещё `tls` и не различает регистр (проверено).
9. Cloudflared `protocol`: документация — `quic`, `http2`; код принимает также `auto` (и пустое значение) и `h2mux` (как `http2`) (проверено).
10. `tcp_keep_alive_interval` в документации listen без пометки версии; по changelog все три поля keep-alive появились в listen-полях в 1.13.
11. Документация `strict_route` для Windows обещает защиту от утечки DNS; в коде блокировка порта 53 ставится только при `dns_mode: hijack` (умолчание), при `native` её нет. «Недоступность неподдерживаемых сетей» на Windows сводится к запрету IPv6, когда у адаптера нет IPv6-адреса.
12. У hysteria2 `obfs` типа `salamander` лишние поля (`min_packet_size` и др.) молча отбрасываются, хотя везде в конфиге лишний ключ — ошибка.
13. Документация hysteria2 называет `ignore_client_bandwidth` несовместимым с `up_mbps`/`down_mbps`; check сочетание не отвергает.
14. Документация vmess, trojan, vless и anytls называет `users` обязательным; код принимает пустой список (кроме shadowtls v3 и naive).
15. `dns_mode` не проверяется на допустимые значения; неизвестное ведёт себя как `native`.

Не проверено запуском (только по коду): паника tun при `/32` без IPv6 и без `dns_address`; ошибка старта `tproxy` и `netns` в listen-полях на Windows; ошибка каждого соединения `redirect` на Windows; поведение прокси WinINet после убийства процесса; поддержка TFO слушателем на Windows (по тегам сборки tfo-go).

Исходники раздела: см. разделы выше; документация: docs/configuration/inbound/*.md, docs/configuration/shared/listen.md, docs/changelog.md, docs/deprecated.md, docs/schema.json.
