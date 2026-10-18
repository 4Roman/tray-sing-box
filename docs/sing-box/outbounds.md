# Исходящие (outbounds) и эндпоинты (endpoints) — sing-box 1.14.2

Справочник по интерфейсу sing-box **1.14.2**. Исходящий (`outbounds[]`) — объект, через который sing-box отправляет соединение дальше: напрямую, через прокси-протокол или через группу других исходящих. Эндпоинт (`endpoints[]`, с 1.11) — протокол, который одновременно принимает и отправляет трафик (WireGuard, Tailscale, OpenConnect, OpenVPN); для маршрутизации он неотличим от исходящего.

Смежные файлы: общие блоки (dial-поля, listen-поля, TLS, V2Ray-транспорты, multiplex, UDP over TCP, QUIC/HTTP2, UDP NAT) — [shared.md](shared.md); HTTP-клиент и `http_clients` — [config.md](config.md#http_clients); pre-match — [route.md](route.md#pre-match); входящие — [inbounds.md](inbounds.md); DNS-серверы, в том числе `tailscale`, `openvpn`, `openconnect` — [dns.md](dns.md); `route.final`, правила и действия маршрутизации — [route.md](route.md); `cache_file` и переключение selector через API — [experimental.md](experimental.md); правила разбора JSON и верхний уровень конфига — [config.md](config.md); сводка устаревшего — [deprecations.md](deprecations.md); команды `check`/`generate` — [cli.md](cli.md).

## Условные обозначения

- Типы записаны как типы JSON: `string`, `int`, `bool`, `object`, `[object]`, `[string]` (только массив).
- `string|[string]` — поле типа `badoption.Listable`: одно значение без скобок или массив.
- `duration` — строка в синтаксисе длительностей Go (`"30s"`, `"1h30m"`); число вместо строки — ошибка разбора. `udp_timeout` местами принимает и число секунд — это оговорено у поля.
- `size` — объём памяти: число байт или строка с единицей (`"8 MB"`, `"8MB"`); `KiB`/`MiB` не принимаются (проверено). Подробности — [shared.md](shared.md).
- `prefix` — IP-префикс CIDR (`"10.0.0.2/32"`); голый адрес без `/` — ошибка разбора (проверено).
- `-> outbound`, `-> dns server`, `-> http_client` — ссылка по тегу.
- «с 1.X» — поле или тип появились в версии 1.X (отмечается для 1.10 и новее).
- «check» — `sing-box check`: разбор JSON и `box.New` (создание всех объектов), без `Start`. «При старте» — ошибка в `Start`, check её не видит. «При подключении» — проверка при первом использовании.
- «Проверено» — опыт на официальном `sing-box.exe` 1.14.2 для Windows (`check`), без запуска.

## Общие поля и разбор JSON

У каждого элемента `outbounds[]` и `endpoints[]` есть два общих поля; остальные зависят от `type`.

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `type` | string | — (обязательно) | Тип. Неизвестный — ошибка разбора `unknown outbound type: X` / `unknown endpoint type: X`; отсутствующий — то же с пустым именем. |
| `tag` | string | индекс элемента в списке (`"0"`, `"1"`, …) | Имя, по которому на объект ссылаются `detour`, группы, правила, `route.final`. |

Особенности разбора (проверено):

- `type` и `tag` нужно писать строго строчными. Ключ `"Type"` или `"Tag"` сначала опознаётся для выбора типа, но затем остаётся «лишним» и даёт ошибку разбора `outbounds[0].Type: json: unknown field "Type"` (так же у эндпоинтов).
- Все остальные ключи сопоставляются без учёта регистра, в том числе вложенные: `"SERVER"`, `"Server_Port"`, `"Detour"`, `"TLS": {"Enabled": true, "Server_Name": …}` понимаются как обычные. Принимаются и юникодные «двойники» из правил свёртки Go (`"ſerver"` = `server`). Общее правило — в [config.md](config.md).
- Неизвестный ключ — ошибка разбора (`json: unknown field`). Исключения, где лишний ключ молча игнорируется: объект `obfs` типа `salamander` у hysteria2 (проверено) и `domain_resolver` (см. [shared.md](shared.md)).
- Пустой `tag` заменяется номером элемента. Теги исходящих и эндпоинтов проверяются на уникальность вместе, по уже подставленным номерам: безымянный исходящий №0 и безымянный эндпоинт №0 оба получают `"0"` — ошибка `duplicate outbound/endpoint tag: 0`; исходящий с явным `"tag": "0"` конфликтует с безымянным нулевым.

Исходники: option/outbound.go, option/endpoint.go, option/options.go (`checkOutbounds`), box.go, include/registry.go.

## Сводка типов исходящих

Столбцы блоков: dial — [dial-поля](shared.md#поля-подключения-dial); TLS — [исходящий TLS](shared.md#исходящий-tls-клиент) (`обяз.` — без `tls.enabled: true` check выдаёт `TLS required`); transport — [V2Ray-транспорт](shared.md#v2ray-транспорты-transport); mux — [multiplex](shared.md#мультиплексирование-multiplex); UoT — [udp_over_tcp](shared.md#udp-over-tcp-udp_over_tcp); QUIC — [QUIC Fields](shared.md#параметры-quic-quic-fields).

| Тип | С | dial | TLS | transport | mux | UoT | QUIC | Сети | Сборка, Windows |
|---|---|---|---|---|---|---|---|---|---|
| `direct` | — | да, без `detour` | — | — | — | — | — | tcp, udp, icmp | |
| `block` | — | — | — | — | — | — | — | tcp, udp | |
| `bridge` | 1.14 | — | — | — | — | — | — | только L3 (tcp, udp, icmp) | Windows только x86/x64, WinDivert, права администратора |
| `socks` | — | да | — | — | — | да | — | `network` | |
| `http` | — | да | опц. | — | — | — | — | tcp | |
| `shadowsocks` | — | да | — | — | да | да | — | `network` | |
| `vmess` | — | да | опц. | да | да | — | — | `network` | |
| `trojan` | — | да | опц. | да | да | — | — | `network` | |
| `vless` | — | да | опц. | да | да | — | — | `network` | |
| `shadowtls` | — | да | обяз. | — | — | — | — | tcp | |
| `anytls` | 1.12 | да, без TFO | обяз. | — | — | — | — | tcp, udp | |
| `snell` | 1.14 | да | — | — | — | — | — | `network` | |
| `hysteria` | — | да | обяз. | — | — | — | да (с 1.14) | `network` | тег `with_quic` |
| `hysteria2` | — | да | обяз. | — | — | — | да (с 1.14) | `network` | тег `with_quic` |
| `tuic` | — | да | обяз. | — | — | — | да (с 1.14) | `network` | тег `with_quic` |
| `naive` | 1.13 | да | обяз., урезанный | — | — | да | — | tcp; +udp при UoT | тег `with_naive_outbound`; на Windows нужен `libcronet.dll` |
| `ssh` | — | да | — | — | — | — | — | tcp | |
| `tor` | — | да | — | — | — | — | — | tcp | внешний исполняемый `tor` |
| `selector` | — | — | — | — | — | — | — | как у выбранного | |
| `urltest` | — | — | — | — | — | — | — | tcp, udp (выбор раздельный) | |
| `dns` | удалён в 1.13 | | | | | | | | |
| `wireguard` | удалён в 1.13 | | | | | | | | заменён эндпоинтом |
| `shadowsocksr` | удалён в 1.6 | | | | | | | | |

Исходники: include/registry.go, include/quic.go, include/naive_outbound.go, constant/proxy.go, docs/schema.json.

## Сводка типов эндпоинтов

| Тип | С | dial | Сети | Сборка |
|---|---|---|---|---|
| `wireguard` | 1.11 | да | tcp, udp, icmp; L3 | `with_wireguard`; при `system: false` ещё `with_gvisor` |
| `tailscale` | 1.12 | да (только к серверу управления) | tcp, udp, icmp; L3 | `with_tailscale` |
| `openconnect` | 1.14 | да | tcp, udp, icmp | `with_openconnect`; при `system: false` ещё `with_gvisor` |
| `openvpn-client` | 1.14 | да | tcp, udp, icmp | `with_openvpn`; при `system: false` ещё `with_gvisor` |
| `openvpn-server` | 1.14 | нет, [listen-поля](shared.md#поля-прослушивания-listen) | tcp, udp, icmp | `with_openvpn`; при `system: false` ещё `with_gvisor` |

Исходники: include/registry.go, include/wireguard.go, include/tailscale.go, include/openconnect.go, include/openvpn.go и их `*_stub.go`.

## Сборка: build-теги и официальный релиз для Windows

- Официальный `sing-box-1.14.2-windows-amd64` собран с тегами `with_gvisor,with_quic,with_dhcp,with_wireguard,with_utls,with_acme,with_clash_api,with_tailscale,with_ccm,with_ocm,with_cloudflared,with_naive_outbound,with_purego,with_usbip,with_openvpn,with_openconnect,badlinkname,tfogo_checklinkname0` (проверено командой `version`; совпадает с `release/DEFAULT_BUILD_TAGS_WINDOWS`). Все типы этого файла в нём есть.
- Если тег не задан при сборке, тип всё равно зарегистрирован заглушкой: разбор проходит, а check падает с сообщением вида `… is not included in this build, rebuild with -tags with_…` (для QUIC-типов — `QUIC is not included in this build`).
- `naive` в сборке с `with_purego` загружает `libcronet.dll` во время `box.New`. Без DLL рядом с `sing-box.exe` или в `PATH` check любой конфигурации с исходящим `naive` падает: `cronet: library not found. Place libcronet.dll in the executable directory or PATH` (проверено копией `sing-box.exe` без DLL). Ошибки самих опций (`TLS required`, запрещённые поля TLS, неизвестный `quic_congestion_control`) выводятся раньше и без DLL (проверено). Официальный архив для Windows содержит `libcronet.dll` (шаг сборки `Extract libcronet.dll` в `.github/workflows/build.yml`).
- `tor`: встроенного Tor в исходниках 1.14.2 нет. Документация упоминает тег `with_embedded_tor`, но ни один файл дерева его не использует; исходящий всегда запускает внешний исполняемый `tor`.
- `bridge` на Windows работает через драйвер WinDivert, встроенный в `sing-box.exe` (только amd64 и 386). На arm64 check: `bridge outbound is only supported on Linux, macOS, Windows (x86 and x64), rooted Android and jailbroken iOS`.

Исходники: release/DEFAULT_BUILD_TAGS_WINDOWS, Makefile, include/*.go, protocol/naive/outbound.go, protocol/tor/outbound.go, protocol/bridge/backend_*.go, common/windivert/.

## Пространство тегов, detour и порядок старта

Исходящие и эндпоинты делят одно пространство тегов. Везде, где ожидается тег исходящего (`detour` в dial-полях, члены и `default` групп, `outbound` в правилах, `route.final`), sing-box ищет сначала среди исходящих, затем среди эндпоинтов. Совпадение тегов между ними — ошибка разбора (см. выше).

Исходящий по умолчанию: тег из `route.final`; если он пуст — первый элемент `outbounds[]` (эндпоинт по умолчанию не становится никогда); если исходящих нет — встроенный `direct` с тегом `direct`. `route.final` на несуществующий тег — ошибка при старте `default outbound not found` (подробнее — [route.md](route.md)).

Зависимости и старт:

- Зависимостью считаются: `detour` из dial-полей (у всех исходящих с dial-полями и у эндпоинтов `wireguard`, `openvpn-client`, `openconnect`) и список `outbounds` групп `selector`/`urltest`. У `tailscale` и `openvpn-server` зависимостей нет: `detour` tailscale в граф не входит.
- При старте исходящие и эндпоинты запускаются так, чтобы зависимость стартовала раньше. Несуществующий тег — `dependency[X] not found for outbound[Y]`, кольцо (в том числе `detour` на себя или группа, содержащая себя) — `circular outbound dependency: A -> B -> A`. Это ошибки старта: check их не видит (проверено: `detour` на отсутствующий тег, кольцо из двух `detour`, selector с отсутствующим членом, selector, содержащий себя, — check завершается с кодом 0). Проверка идёт по всем объектам, даже по тем, куда не попадает трафик.
- `detour` на «пустой» `direct` (без единого dial-поля): у исходящих ошибка `detour to an empty direct outbound makes no sense` возникает только при первом соединении, у DNS-серверов — при старте ([dns.md](dns.md)).
- `detour` у самого `direct` запрещён: check — `` `detour` is not supported in direct context`` (проверено).
- У `tailscale` отсутствующий `detour` check пропускает (проверено) и не ловит при сортировке старта; ошибка появится, когда эндпоинт начнёт соединяться с сервером управления.

Исходники: adapter/outbound/manager.go (`Outbound`, `Start`, `startOutbounds`, `Create`), adapter/outbound/adapter.go, adapter/endpoint/manager.go, common/dialer/detour.go, box.go.

## Поле network

У socks, shadowsocks, vmess, trojan, vless, snell, hysteria, hysteria2, tuic есть поле `network`: какие сети исходящий обслуживает.

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `network` | string\|[string] | обе (`tcp` и `udp`) | Допустимы `tcp` и `udp`; иное (например `icmp`) — ошибка разбора `unknown network`. Пустой массив равен значению по умолчанию. |

Как действует: соединение, сеть которого исходящий не обслуживает, маршрутизатор отвергает при подключении (`UDP is not supported by outbound: X`); `urltest` пропускает такие члены при выборе для этой сети. У hysteria/hysteria2 без `udp` клиент вообще не включает UDP-релей. Сети типов без поля `network` фиксированы (см. сводку).

Исходники: option/types.go (`NetworkList`), route/route.go, protocol/group/urltest.go.

## direct

Отправляет соединение напрямую из системы. С 1.13 обслуживает и ICMP (ping). Доменные адреса назначения резолвит сам — через `domain_resolver` или `route.default_domain_resolver`.

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| dial-поля | — | — | Все [dial-поля](shared.md#поля-подключения-dial), кроме `detour` (check: `` `detour` is not supported in direct context``). `udp_fragment` по умолчанию `true`. Устаревший `domain_strategy` в 1.14.2 без переменной окружения фатален (проверено; см. [shared.md](shared.md#domain_strategy-устаревшее)). |
| `override_address` | string | — | Удалено в 1.13: любое непустое значение — ошибка разбора с указанием на действие `route-options` (проверено). |
| `override_port` | int | — | Удалено в 1.13, аналогично. |
| `proxy_protocol` | int | — | Удалено в 1.6: ненулевое значение — check `Proxy Protocol is deprecated and removed in sing-box 1.6.0` (проверено). |

«Пустой» direct — без единого dial-поля: на него нельзя ссылаться как на `detour` (см. раздел о зависимостях).

Исходники: option/direct.go, protocol/direct/outbound.go.

## block

Отвергает любое соединение (ошибка `EPERM`), в журнал пишется `blocked connection`. Полей нет: любое, включая `detour`, — ошибка разбора (проверено). В документации тип значится устаревшим с 1.11 и «удалённым в 1.13», но в 1.14.2 он зарегистрирован и работает без предупреждений (проверено); замена — действие `reject` в правилах ([route.md](route.md)).

Исходники: protocol/block/outbound.go, option/simple.go (`StubOptions`).

## bridge

с 1.14. L3-аналог `direct`: пересылает L3-трафик (TCP, UDP, ICMP) из TUN или других L3-эндпоинтов прямо в сетевой интерфейс, без перевода в L4. Направлять трафик нужно действием `route` на этапе [pre-match](route.md#pre-match); обычные L4-соединения отвергаются, как и адреса самой машины. Требует привилегий.

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `interface` | string | интерфейс по умолчанию | Через какой интерфейс выпускать трафик. Пока интерфейс недоступен, трафик отбрасывается. На Windows — единственное действующее поле. |
| `bridge_name` | string | `bridge` | Префикс имени служебного TUN-интерфейса. На Apple не действует; на Windows не используется (там WinDivert, а не TUN). |
| `iproute2_table_index` | int | `2200` + номер экземпляра | Только Linux и только при заданном `interface`: таблица маршрутов для закреплённого выхода. |
| `iproute2_rule_index` | int | `100` | Только Linux: начальный номер правил iproute2. |

Dial-полей нет. Windows: только x86/x64, драйвер WinDivert встроен в exe; без прав администратора ошибка при старте `bridge: open injection handle (Administrator required)`. check на Windows x64 проходит (проверено). Рекомендуемый «шлюз» в правиле — условие `preferred_by`.

Исходники: option/bridge.go, protocol/bridge/outbound.go, protocol/bridge/backend_windows.go, protocol/bridge/backend_stub.go, common/windivert/; документация: docs/configuration/outbound/bridge.md.

## socks

Клиент SOCKS4/4a/5.

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `server` | string | — (обязательно по документации) | Адрес сервера. Пустое значение check не отвергает (проверено на trojan, общее для всех типов с `server`): ошибка — при подключении. |
| `server_port` | int | — (обязательно) | Порт. |
| `version` | string | `5` | `4`, `4a`, `5`. Строго строка: число `5` — ошибка разбора (проверено); иное значение — check `unknown socks version`. У SOCKS4 домен назначения резолвится локально DNS-маршрутизатором sing-box, у 4a и 5 передаётся серверу. |
| `username` | string | — | Имя пользователя (у SOCKS4 — user ID). |
| `password` | string | — | Пароль (только SOCKS5). |
| `network` | string\|[string] | обе | См. [network](#поле-network). UDP работает через UDP ASSOCIATE SOCKS5 или через `udp_over_tcp`. |
| `udp_over_tcp` | bool\|object | выключено | [UDP over TCP](shared.md#udp-over-tcp-udp_over_tcp). |
| dial-поля | — | — | [Dial-поля](shared.md#поля-подключения-dial). |

Исходники: option/simple.go (`SOCKSOutboundOptions`), protocol/socks/outbound.go.

## http

Клиент прокси HTTP CONNECT, только TCP (поля `network` нет — ошибка разбора, проверено).

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `server` | string | — (обязательно) | Адрес прокси. |
| `server_port` | int | — (обязательно) | Порт. |
| `username` | string | — | Basic-авторизация: имя. |
| `password` | string | — | Basic-авторизация: пароль. Без TLS уходит в открытом виде. |
| `path` | string | — | Путь HTTP-запроса. |
| `headers` | object | — | Дополнительные заголовки запроса; значение — `string` или `[string]` (проверено). |
| `tls` | object | выключен | [Исходящий TLS](shared.md#исходящий-tls-клиент) до прокси (HTTPS-прокси). |
| dial-поля | — | — | [Dial-поля](shared.md#поля-подключения-dial). |

Исходники: option/simple.go (`HTTPOutboundOptions`), protocol/http/outbound.go.

## shadowsocks

Клиент Shadowsocks (AEAD, 2022 и устаревшие потоковые шифры).

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `server` | string | — (обязательно) | Адрес сервера. |
| `server_port` | int | — (обязательно) | Порт. |
| `method` | string | — (обязательно) | Метод, список ниже. Пустой или неизвестный — check `unknown method: X` (проверено). |
| `password` | string | — (обязательно, кроме `none`) | Пароль. Для методов `2022-*` — ключ в base64 (16 байт для `2022-blake3-aes-128-gcm`, 32 — для двух других); не base64 — check `decode key: illegal base64 data`. Несколько ключей через `:` (ключи ретрансляторов/мультипользовательского сервера) принимаются (проверено). Без пароля у прочих методов — check `missing password`; у `none` пароль не нужен. |
| `plugin` | string | — | Встроенный SIP003-плагин: только `obfs-local` или `v2ray-plugin` (внешние программы не запускаются). Иное — check `plugin not found: X` (проверено для `kcptun`, `simple-obfs`). |
| `plugin_opts` | string | — | Параметры плагина строкой `ключ=значение;…`. `obfs-local`: `obfs=http\|tls`, `obfs-host=…`; неверный режим — check `unknown obfs mode`. `v2ray-plugin`: режим `mode=quic` без `tls` — check `TLS required` (проверено). |
| `network` | string\|[string] | обе | См. [network](#поле-network). |
| `udp_over_tcp` | bool\|object | выключено | [UDP over TCP](shared.md#udp-over-tcp-udp_over_tcp). При включённом `multiplex` молча отключается мультиплексор (документация называет это конфликтом, check его не отвергает — проверено). |
| `multiplex` | object | выключено | [Multiplex](shared.md#мультиплексирование-multiplex). |
| dial-поля | — | — | [Dial-поля](shared.md#поля-подключения-dial). |

Методы, которые принимает 1.14.2 (все 18 проверены через check): `none`; AEAD — `aes-128-gcm`, `aes-192-gcm`, `aes-256-gcm`, `chacha20-ietf-poly1305`, `xchacha20-ietf-poly1305`; Shadowsocks 2022 — `2022-blake3-aes-128-gcm`, `2022-blake3-aes-256-gcm`, `2022-blake3-chacha20-poly1305`; устаревшие потоковые — `aes-128-ctr`, `aes-192-ctr`, `aes-256-ctr`, `aes-128-cfb`, `aes-192-cfb`, `aes-256-cfb`, `rc4-md5`, `chacha20-ietf`, `xchacha20`. Не принимаются (проверено): `chacha20-poly1305`, `xchacha20-poly1305`, `chacha20`, `rc4`, `salsa20`, `bf-cfb`, `camellia-128-cfb`, `table`, `plain`, `aes-128-gcm-siv`, `2022-blake3-chacha8-poly1305`.

Исходники: option/shadowsocks.go, protocol/shadowsocks/outbound.go, transport/sip003/.

## vmess

Клиент VMess.

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `server` | string | — (обязательно) | Адрес сервера. |
| `server_port` | int | — (обязательно) | Порт. |
| `uuid` | string | — (обязательно) | Идентификатор пользователя. check формат не проверяет: строка не-UUID и даже пустая проходят (проверено). Строка, которая не разбирается как UUID, превращается в UUIDv5 от этой строки с нулевым пространством имён, как в Xray (библиотека sing-vmess v0.2.8 из go.mod: `client.go`, `vless/client.go`; сверено редактором по исходнику библиотеки). |
| `security` | string | `auto` | Шифрование: `auto`, `none`, `zero`, `aes-128-gcm`, `chacha20-poly1305`, устаревшее `aes-128-cfb`. Иное — check `vmess: unsupported security type` (проверено; `aes-128-ctr` из документации отвергается). `auto` при включённом TLS превращается в `zero`, без TLS алгоритм выбирает библиотека. |
| `alter_id` | int | `0` | `0` — протокол AEAD; `1` и больше — старый протокол (значения выше 1 работают как 1). Ненулевое значение check принимает (проверено); серверы V2Ray/Xray давно требуют AEAD. |
| `global_padding` | bool | `false` | Случайное дополнение трафика (в v2ray включено всегда). |
| `authenticated_length` | bool | `false` | Шифровать поле длины блока. |
| `network` | string\|[string] | обе | См. [network](#поле-network). |
| `tls` | object | выключен | [Исходящий TLS](shared.md#исходящий-tls-клиент). |
| `packet_encoding` | string | пусто (выключено) | Кодирование UDP: пусто — обычный UDP VMess, `packetaddr` (v2ray 5+), `xudp` (Xray, full-cone). Иное — check `unknown packet encoding`. |
| `multiplex` | object | выключено | [Multiplex](shared.md#мультиплексирование-multiplex). |
| `transport` | object | нет (TCP) | [V2Ray-транспорт](shared.md#v2ray-транспорты-transport): `http`, `ws`, `quic`, `grpc`, `httpupgrade`. |
| dial-поля | — | — | [Dial-поля](shared.md#поля-подключения-dial). |

Исходники: option/vmess.go, protocol/vmess/outbound.go.

## trojan

Клиент Trojan.

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `server` | string | — (обязательно) | Адрес сервера. |
| `server_port` | int | — (обязательно) | Порт. |
| `password` | string | — (обязательно по документации) | Пароль. Отсутствие check не отвергает (проверено). |
| `network` | string\|[string] | обе | См. [network](#поле-network). |
| `tls` | object | выключен | [Исходящий TLS](shared.md#исходящий-tls-клиент). Протокол рассчитан на TLS, но без него check проходит (проверено). |
| `multiplex` | object | выключено | [Multiplex](shared.md#мультиплексирование-multiplex). |
| `transport` | object | нет | [V2Ray-транспорт](shared.md#v2ray-транспорты-transport). |
| dial-поля | — | — | [Dial-поля](shared.md#поля-подключения-dial). |

Исходники: option/trojan.go, protocol/trojan/outbound.go.

## vless

Клиент VLESS.

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `server` | string | — (обязательно) | Адрес сервера. |
| `server_port` | int | — (обязательно) | Порт. |
| `uuid` | string | — (обязательно) | Идентификатор. Как у vmess: check формат не проверяет, пустая строка проходит (проверено). |
| `flow` | string | пусто | Подпротокол. Единственное допустимое значение — `xtls-rprx-vision`; `xtls-rprx-vision-udp443`, `xtls-rprx-direct`, `xtls-rprx-splice` и прочие — check `unsupported flow` (проверено). Сочетания vision без TLS, с `multiplex` или с `transport` check не отвергает (проверено). Непустой `flow` отключает kTLS. |
| `network` | string\|[string] | обе | См. [network](#поле-network). |
| `tls` | object | выключен | [Исходящий TLS](shared.md#исходящий-tls-клиент), включая Reality. |
| `packet_encoding` | string | `xudp`, если поле отсутствует | Кодирование UDP: `xudp`, `packetaddr` или явная пустая строка `""` (выключено). Отсутствие поля и `""` — разные вещи. Иное — check `unknown packet encoding`. |
| `multiplex` | object | выключено | [Multiplex](shared.md#мультиплексирование-multiplex). |
| `transport` | object | нет | [V2Ray-транспорт](shared.md#v2ray-транспорты-transport). |
| dial-поля | — | — | [Dial-поля](shared.md#поля-подключения-dial). |

Исходники: option/vless.go, protocol/vless/outbound.go.

## shadowtls

Клиент ShadowTLS: маскирует соединение под TLS-рукопожатие с настоящим сайтом. Сам данные не проксирует и адрес назначения игнорирует — обычно служит `detour` для shadowsocks или другого исходящего. Только TCP.

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `server` | string | — (обязательно) | Адрес сервера ShadowTLS. |
| `server_port` | int | — (обязательно) | Порт. |
| `version` | int | `1` | Версия протокола `1`, `2`, `3`; иное — check `unknown protocol version` (проверено для `4`). У версии 1 TLS принудительно ограничен версией 1.2. |
| `password` | string | — | Пароль, нужен версиям 2 и 3. Отсутствие check не отвергает (проверено). |
| `tls` | object | — (обязательно) | [Исходящий TLS](shared.md#исходящий-tls-клиент), `enabled: true` обязателен. `server_name` — сайт, под который идёт маскировка. uTLS допускается (проверено). |
| dial-поля | — | — | [Dial-поля](shared.md#поля-подключения-dial). |

Исходники: option/shadowtls.go, protocol/shadowtls/outbound.go.

## anytls

с 1.12. Клиент AnyTLS: TLS-туннель с пулом сессий и случайным дополнением.

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `server` | string | — (обязательно) | Адрес сервера. |
| `server_port` | int | — (обязательно) | Порт. |
| `password` | string | — (обязательно по документации) | Пароль. Отсутствие check не отвергает (проверено). |
| `idle_session_check_interval` | duration | `30s` | Как часто проверять простаивающие сессии. |
| `idle_session_timeout` | duration | `30s` | Сессии, простаивающие дольше, при проверке закрываются. |
| `min_idle_session` | int | `0` | Сколько простаивающих сессий сохранять при проверке в любом случае. |
| `client_metadata` | string | — | с 1.13.16 (по документации). Метаданные клиента для сервера; формат описан в docs/manual/misc/anytls-client-metadata.md. |
| `tls` | object | — (обязательно) | [Исходящий TLS](shared.md#исходящий-tls-клиент), `enabled: true` обязателен. |
| dial-поля | — | — | [Dial-поля](shared.md#поля-подключения-dial); `tcp_fast_open: true` — check `tcp_fast_open is not supported with anytls outbound` (проверено). |

Поля `network` нет: TCP и UDP обслуживаются всегда.

Исходники: option/anytls.go, protocol/anytls/outbound.go.

## snell

с 1.14. Клиент Snell (Surge). Набор полей зависит от `version`: общая часть плюс поля версии 4 или 6. Версии 5 у клиента нет (её QUIC-режим не реализован, а протокол совпадает с v4).

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `version` | int | — (обязательно) | `4` или `6`. Отсутствует — ошибка разбора `snell: missing version`; `5` и прочие — `snell: unsupported version` (проверено). |
| `server` | string | — (обязательно) | Адрес сервера. |
| `server_port` | int | — (обязательно) | Порт. |
| `psk` | string | — (обязательно) | Общий ключ. Пустой — check `snell: missing pre-shared key` (проверено). Для v6 документация требует 12–255 байт, но check короткий ключ пропускает (проверено). |
| `userkey` | string | — | Ключ пользователя для многопользовательского сервера. |
| `reuse` | bool | `false` | Переиспользование соединений (команда `CONNECT` Snell v2). |
| `network` | string\|[string] | обе | См. [network](#поле-network). |
| `obfs_mode` | string | `none` | Только v4: HTTP-обфускация `none`, `http`; код принимает и `tls` (проверено), документация о нём молчит. У v6 поле — ошибка разбора `unknown field` (проверено). |
| `obfs_host` | string | `bing.com` | Только v4: заголовок `Host` при `obfs_mode: http`. |
| `mode` | string | `default` | Только v6: формирование трафика `default`, `unshaped`, `unsafe-raw`; иное — check `snell: unknown v6 mode`. У v4 поле — ошибка разбора (проверено). |
| dial-поля | — | — | [Dial-поля](shared.md#поля-подключения-dial). |

Исходники: option/snell.go, protocol/snell/outbound.go; библиотека sing-snell.

## hysteria

Клиент Hysteria v1 (QUIC).

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `server` | string | — (обязательно) | Адрес сервера. |
| `server_port` | int | — (обязательно) | Порт. |
| `server_ports` | string\|[string] | — | с 1.12. Диапазоны портов для «прыжков» в формате `"начало:конец"`. По документации конфликтует с `server_port`, но вместе check их пропускает. |
| `hop_interval` | duration | `30s` | с 1.12. Интервал смены порта. Меньше `5s` check пропускает (проверено на hysteria2), а подключение через диапазон портов падает: `hop interval must be at least 5 seconds` (по коду sing-quic `hysteria/hop.go`). |
| `up` | string\|int | — | Скорость отдачи строкой `число [пробел] единица`: сетевые единицы `Bps`, `Kbps`, `KBps`, `Mbps`, `MBps`, `Gbps`, `GBps`, `Tbps`, `TBps` (b — биты, B — байты, основание 1000; регистр важен: `mbps` — ошибка). Если сетевая единица не подошла, строка разбирается как объём в байтах без учёта регистра: `B`, `k`/`KB`, `M`/`MB`, `G`/`GB`… (основание 1000) и `Ki`/`KiB`, `Mi`/`MiB`… (основание 1024) — то есть `"100 Mb"` значит 100 **мегабайт**/с, а не мегабит (тип `NetworkBytesCompat` библиотеки sing; принятие форм проверено check, смысл — по исходнику библиотеки). Единица `bps` из документации в 1.14.2 отвергается (`unsupported unit`), строка без единицы тоже (`invalid format`). Число без кавычек — байты в секунду. Имеет приоритет над `up_mbps`. |
| `up_mbps` | int | — | Скорость отдачи в Мбит/с. Нужно `up` или `up_mbps`: без обоих — check `missing upload speed`; меньше 16384 байт/с (≈131 кбит/с) — `invalid upload speed` (проверено). |
| `down` | string\|int | — | Скорость приёма, формат как у `up`. |
| `down_mbps` | int | — | Скорость приёма в Мбит/с; без обоих — `missing download speed`. |
| `obfs` | string | — | Пароль обфускации (xplus). |
| `auth` | string | — | Пароль аутентификации в base64 (байты); не base64 — ошибка разбора (проверено). |
| `auth_str` | string | — | Пароль строкой; при заданном имеет приоритет над `auth`. |
| `network` | string\|[string] | обе | См. [network](#поле-network). |
| `tls` | object | — (обязательно) | [Исходящий TLS](shared.md#исходящий-tls-клиент), `enabled: true` обязателен. |
| QUIC-поля | — | — | с 1.14, [QUIC Fields](shared.md#параметры-quic-quic-fields). |
| `recv_window_conn` | int | — | Устарело в 1.14 (удаление обещано в 1.16), предупреждения не выводится (проверено). По коду переносится в `connection_receive_window`, если тот не задан. |
| `recv_window` | int | — | Устарело в 1.14; по коду переносится в `stream_receive_window`. |
| `disable_mtu_discovery` | bool | `false` | Устарело в 1.14; по коду равносильно `disable_path_mtu_discovery`. |
| dial-поля | — | — | [Dial-поля](shared.md#поля-подключения-dial); `udp_fragment` по умолчанию `true`. |

Исходники: option/hysteria.go, protocol/hysteria/outbound.go, protocol/hysteria/quic.go.

## hysteria2

Клиент Hysteria2 (QUIC). С 1.14 рукопожатие по умолчанию имитирует QUIC браузера Chrome.

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `server` | string | — (обязательно без `realm`) | Адрес сервера. Конфликтует с `realm`. |
| `server_port` | int | — | Порт; игнорируется при заданном `server_ports`. Конфликтует с `realm`. Без порта и диапазонов check проходит (проверено). |
| `server_ports` | string\|[string] | — | с 1.11. Диапазоны `"начало:конец"`; один порт записывается как `"443:443"`. Дефис (`"20000-30000"`) или одиночное число (`"443"`) — check `bad port range` (проверено). |
| `hop_interval` | duration | `30s` | с 1.11. Интервал смены порта. Число вместо строки — ошибка разбора (проверено). Меньше `5s` check пропускает (проверено), при подключении через `server_ports` — ошибка `hop interval must be at least 5 seconds`. |
| `hop_interval_max` | duration | — | с 1.14. Если задан, интервал каждый раз выбирается случайно между `hop_interval` и этим значением. Ни значение меньше `hop_interval`, ни `hop_interval_max` без `hop_interval` check не отвергает (проверено); по коду sing-quic (`hysteria/hop.go`) подключение через `server_ports` тогда падает: `min hop interval must not be greater than max hop interval` / `min and max hop interval must both be set`. |
| `up_mbps` | int | — | Предел отдачи, Мбит/с. Если скорости не заданы, вместо Brutal используется BBR. Строка — ошибка разбора (проверено). |
| `down_mbps` | int | — | Предел приёма, Мбит/с. |
| `obfs` | object | нет | Обфускация QUIC, поля ниже. |
| `obfs.type` | string | — (обязательно внутри `obfs`) | `salamander` или `gecko` (с 1.14). Пустой или иной — ошибка разбора `unknown obfs type` (проверено). |
| `obfs.password` | string | — (обязательно) | Пароль обфускации; пустой — check `missing obfs password` (проверено). |
| `obfs.min_packet_size` | int | `512` | с 1.14, только `gecko`: минимальный размер пакета в сети. `min` больше `max` — check `gecko: invalid packet size range` (проверено). У `salamander` поле (как и любой лишний ключ) молча игнорируется (проверено). |
| `obfs.max_packet_size` | int | `1200` | с 1.14, только `gecko`: максимальный размер пакета. Больше 2048 — та же ошибка `gecko: invalid packet size range` (по коду sing-quic `hysteria2/client.go`). |
| `password` | string | — | Пароль. Режим userpass официального клиента не поддерживается: пишите `имя:пароль` целиком. |
| `network` | string\|[string] | обе | См. [network](#поле-network). |
| `tls` | object | — (обязательно) | [Исходящий TLS](shared.md#исходящий-tls-клиент), `enabled: true` обязателен. При `realm` SNI по умолчанию — хост из `realm.server_url`. |
| QUIC-поля | — | — | с 1.14, [QUIC Fields](shared.md#параметры-quic-quic-fields). При имитации Chrome `idle_timeout` фиксирован 30 секундами, `max_concurrent_streams` и `initial_packet_size` берутся от Chrome, окна приёма стартуют с начальных значений Chrome. |
| `bbr_profile` | string | `standard` | с 1.14. Профиль BBR: `conservative`, `standard`, `aggressive`; иное — check `unsupported BBR profile` (проверено). |
| `brutal_debug` | bool | `false` | Отладочный журнал алгоритма Brutal. |
| `disable_chrome_parrot` | bool | `false` | с 1.14. Выключить имитацию Chrome. Нужна для сервера с сертификатом Ed25519: Chrome его не заявляет, рукопожатие сорвётся. |
| `realm` | object | нет | с 1.14. Подключение через сервис-«место встречи» Hysteria Realm (обход NAT пробиванием UDP). Конфликтует с `server`, `server_port`, `server_ports` — check `realm conflicts with server, server_port, and server_ports` (проверено). Сервис описан в [experimental.md](experimental.md#service-hysteria-realm). |
| `realm.server_url` | string | — (обязательно) | URL сервиса. Без хоста — check `missing host in realm server_url` (проверено). |
| `realm.token` | string | — | Bearer-токен, должен совпасть с `users[].token` сервиса. |
| `realm.realm_id` | string | — (обязательно по документации) | Идентификатор слота, под которым зарегистрирован сервер. Отсутствие check пропускает (проверено). |
| `realm.stun_servers` | string\|[string] | — (обязательно по документации) | STUN-серверы `host` или `host:port` для определения своего внешнего адреса. Домены резолвятся через `domain_resolver` из dial-полей. Отсутствие check пропускает (проверено). |
| `realm.ip_version` | int | `0` (обе) | `4` или `6`: ограничить STUN, пробивание и итоговый QUIC одной версией IP. Иное — check `invalid IP version` (проверено). |
| `realm.port_mapping` | object | нет | Держать UDP-проброс порта на шлюзе через UPnP или NAT-PMP; сбой не фатален. Требует IPv4: вместе с `ip_version: 6` — check `port mapping requires IPv4` (проверено); по коду достаточно самого объекта, даже с `enabled: false`. |
| `realm.port_mapping.enabled` | bool | `false` | Включить проброс. |
| `realm.port_mapping.timeout` | duration | `10s` | Тайм-аут поиска шлюза и операций проброса. |
| `realm.port_mapping.lifetime` | duration | `10m` | Срок аренды проброса; продлевается на половине срока. |
| `realm.http_client` | string\|object -> http_client | встроенный клиент с умолчаниями (прямое соединение) | [HTTP-клиент](config.md#http_clients) для обращений к сервису: тег из `http_clients` или объект. Без поля создаётся свой клиент с пустыми настройками, то есть без `detour`, напрямую; `route.default_http_client` здесь не используется. Несуществующий тег — ошибка уже в check `create realm http client: http_client not found` (проверено). |
| dial-поля | — | — | [Dial-поля](shared.md#поля-подключения-dial); `udp_fragment` по умолчанию `true`. |

Исходники: option/hysteria2.go, protocol/hysteria2/outbound.go; библиотека sing-quic (go.mod 1.14.2): hysteria/hop.go, hysteria2/client.go, hysteria2/gecko.go; документация: docs/configuration/outbound/hysteria2.md.

## tuic

Клиент TUIC v5 (QUIC).

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `server` | string | — (обязательно) | Адрес сервера. |
| `server_port` | int | — (обязательно) | Порт. |
| `uuid` | string | — (обязательно) | UUID пользователя; в отличие от vmess/vless формат проверяется: пустой или не-UUID — check `invalid uuid` (проверено). |
| `password` | string | — | Пароль пользователя. |
| `congestion_control` | string | `cubic` | `cubic`, `new_reno`, `bbr`; иное — check `unknown congestion control algorithm` (проверено). |
| `udp_relay_mode` | string | `native` | `native` — UDP-датаграммы QUIC; `quic` — UDP внутри QUIC-потоков без потерь, с накладными расходами. Неизвестное значение check молча принимает как `native` (проверено). |
| `udp_over_stream` | bool | `false` | Порт протокола UDP over TCP поверх QUIC-потоков (нужен сервер sing-box). Имеет смысл только для потокового UDP (например QUIC). Вместе с любым непустым `udp_relay_mode`, даже `native`, — check `udp_over_stream is conflict with udp_relay_mode` (проверено). |
| `zero_rtt_handshake` | bool | `false` | 0-RTT при установке QUIC. Уязвимо к повтору пакетов; в документации исходящего поле не описано (описано у входящего). |
| `heartbeat` | duration | `10s` | Интервал heartbeat-пакетов, поддерживающих соединение (умолчание — из документации входящего). |
| `network` | string\|[string] | обе | См. [network](#поле-network). |
| `tls` | object | — (обязательно) | [Исходящий TLS](shared.md#исходящий-tls-клиент); без `enabled: true` — check `TLS required`, даже если объект есть (проверено). |
| QUIC-поля | — | — | с 1.14, [QUIC Fields](shared.md#параметры-quic-quic-fields). |
| dial-поля | — | — | [Dial-поля](shared.md#поля-подключения-dial); `udp_fragment` по умолчанию `true`. |

Исходники: option/tuic.go, protocol/tuic/outbound.go.

## naive

с 1.13. Клиент NaiveProxy на сетевом стеке Chromium (cronet): HTTP/2 или HTTP/3 CONNECT с отпечатком браузера. Нужна сборка с `with_naive_outbound`; в официальном релизе для Windows есть, требуется `libcronet.dll` (см. «Сборка»).

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `server` | string | — (обязательно) | Адрес сервера. Без `tls.server_name` он же служит SNI. |
| `server_port` | int | — (обязательно) | Порт. |
| `username` | string | — | Имя для аутентификации. |
| `password` | string | — | Пароль. |
| `insecure_concurrency` | int | `0` | Число параллельных туннельных соединений. Больше одного облегчает распознавание по анализу трафика. |
| `extra_headers` | object | — | Дополнительные заголовки; значение `string` или `[string]`, но по коду отправляется только первое значение каждого заголовка. |
| `stream_receive_window` | size | QUIC: `6 MB`; HTTP/2: `128 MB` (на iOS `4 MB`) | Окно управления потоком: при `quic` — начальное окно QUIC-потока, иначе окно HTTP/2-сессии (окно потока — половина). |
| `udp_over_tcp` | bool\|object | выключено | [UDP over TCP](shared.md#udp-over-tcp-udp_over_tcp). Без него исходящий обслуживает только TCP. |
| `quic` | bool | `false` | HTTP/3 (QUIC) вместо HTTP/2. |
| `quic_congestion_control` | string | `cubic` (умолчание Chromium) | `bbr`, `bbr2`, `cubic`, `reno`; иное — check `unknown quic congestion control` (проверено). |
| `quic_session_receive_window` | size | `15 MB` | Только при `quic`: начальное окно приёма QUIC-сессии. |
| `tls` | object | — (обязательно) | [Исходящий TLS](shared.md#исходящий-tls-клиент), `enabled: true` обязателен. Читаются только `server_name`, `certificate`, `certificate_path`, `ech` (`config`, `config_path`, `query_server_name`). Явно отвергаются check'ом: `disable_sni`, `insecure`, `alpn`, `min_version`, `max_version`, `cipher_suites`, `curve_preferences`, `client_certificate(_path)`, `client_key(_path)`, `fragment`/`record_fragment`, kTLS, `utls`, `reality` (проверено для `insecure` и `utls`). Прочие поля TLS по коду не читаются. |
| dial-поля | — | — | [Dial-поля](shared.md#поля-подключения-dial). DNS для cronet идёт через DNS-маршрутизатор sing-box (с учётом `domain_resolver`). |

Поля `network` нет.

Исходники: option/naive.go, protocol/naive/outbound.go, include/naive_outbound*.go; документация: docs/configuration/outbound/naive.md.

## ssh

Клиент SSH: TCP-соединения идут через SSH-туннель (direct-tcpip). Только TCP.

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `server` | string | — (обязательно) | Адрес SSH-сервера. |
| `server_port` | int | `22` | Порт. |
| `user` | string | `root` | Пользователь. |
| `password` | string | — | Пароль. Без пароля и ключа check проходит (проверено). |
| `private_key` | string\|[string] | — | Закрытый ключ текстом (строки массива склеиваются переводом строки). Неразборчивый — check `parse private key` (проверено). |
| `private_key_path` | string | — | Путь к ключу; в пути раскрываются переменные окружения в синтаксисе `$VAR`. Файл читается в check: нет файла — ошибка `read private key` (проверено). Используется, только если `private_key` пуст. |
| `private_key_passphrase` | string | — | Пароль зашифрованного ключа. |
| `host_key` | string\|[string] | — (принимать любой) | Допустимые ключи сервера в формате authorized_keys. Пусто — ключ сервера не проверяется. Неразборчивый — check `parse host key` (проверено). |
| `host_key_algorithms` | string\|[string] | умолчания библиотеки | Разрешённые алгоритмы ключа сервера. |
| `client_version` | string | случайная версия OpenSSH | Строка версии клиента. |
| `cipher` | string\|[string] | умолчания библиотеки | с 1.14. Разрешённые шифры. Неизвестные имена check не проверяет (проверено). |
| `mac` | string\|[string] | умолчания библиотеки | с 1.14. Разрешённые MAC. |
| `kex_algorithm` | string\|[string] | умолчания библиотеки | с 1.14. Разрешённые алгоритмы обмена ключами. |
| dial-поля | — | — | [Dial-поля](shared.md#поля-подключения-dial). |

Исходники: option/ssh.go, protocol/ssh/outbound.go.

## tor

Запускает внешний процесс Tor и отправляет через него TCP-соединения. Сам Tor ходит в сеть через служебный локальный SOCKS5-мост sing-box, который использует dial-поля этого исходящего. Процесс стартует при старте sing-box, check его не запускает (проверено: check проходит даже с несуществующим `executable_path`).

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `executable_path` | string | `tor` из `PATH` | Путь к исполняемому Tor. Встроенного Tor в 1.14.2 нет (см. «Сборка»). |
| `extra_args` | [string] | — | Дополнительные аргументы командной строки Tor. Только массив: строка — ошибка разбора (проверено). |
| `data_directory` | string | временный каталог | Каталог данных Tor (раскрываются `$VAR`, относительный путь — от рабочего каталога). Документация настоятельно советует задать: иначе каждый старт очень долгий. В каталоге создаётся пустой `torrc`; лежащие там `geoip`/`geoip6` подключаются автоматически. |
| `torrc` | object | — | Параметры torrc: ключ — имя, значение — строка. Число — ошибка разбора (проверено; пример в документации с `"ClientOnly": 1` не проходит). `Socks5Proxy*` переопределить нельзя. |
| dial-поля | — | — | [Dial-поля](shared.md#поля-подключения-dial) для выхода самого Tor в сеть. |

Поля `network` нет (только TCP). Графические клиенты с политикой безопасности могут запретить тип (`CheckSecurityFeature`).

Исходники: option/tor.go, protocol/tor/outbound.go, common/proxybridge/.

## selector

Ручной выбор одного из исходящих: выбор меняется через Clash API, API-сервис или графический клиент ([experimental.md](experimental.md#переключение-selector-через-api-и-его-сохранение)).

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `outbounds` | [string] -> outbound | — (обязательно) | Члены группы: исходящие, эндпоинты или другие группы. Только массив (строка — ошибка разбора, проверено). Пустой или отсутствующий — check `missing tags` (проверено). Несуществующий тег — ошибка при старте (граф зависимостей). |
| `default` | string -> outbound | первый член | Выбор при старте. Тег вне `outbounds` check пропускает (проверено), при старте — `default outbound not found`. Если включён `experimental.cache_file` и в нём сохранён выбор, существующий в группе, он имеет приоритет, а `default` не проверяется вовсе. |
| `interrupt_exist_connections` | bool | `false` | При смене выбора закрывать и уже открытые входящие соединения. Внутренние соединения sing-box (DNS, загрузки) прерываются всегда. |

Сеть группы — сеть выбранного члена. Выбор сохраняется в `cache_file`, если он включён.

Исходники: option/group.go, protocol/group/selector.go, experimental/cachefile/cache.go.

## urltest

Автоматический выбор члена с наименьшей задержкой по HTTP-тесту. Выбор ведётся отдельно для TCP и UDP (учитываются только члены, обслуживающие соответствующую сеть).

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `outbounds` | [string] -> outbound | — (обязательно) | Члены. Только массив; пустой — check `missing tags`. Вложенные группы допускаются, их члены тестируются рекурсивно. |
| `url` | string | `https://www.gstatic.com/generate_204` | Адрес теста. Неверный URL check пропускает (проверено) — тесты просто не пройдут. |
| `interval` | duration | `3m` | Период тестов. Больше `idle_timeout` — ошибка при старте `interval must be less or equal than idle_timeout`; check пропускает (проверено). |
| `tolerance` | int | `50` | Порог в миллисекундах (0–65535; больше — ошибка разбора, проверено): переключение происходит, только если новый кандидат быстрее текущего больше чем на это значение. `0` заменяется на `50`, нулевой порог задать нельзя (`NewURLTestGroup`). |
| `idle_timeout` | duration | `30m` | Если группой не пользовались дольше, периодические тесты останавливаются до следующего соединения. |
| `interrupt_exist_connections` | bool | `false` | Как у selector: при смене выбора закрывать открытые входящие соединения. |

Как тестирует: соединение через члена, запрос `HEAD` на `url`, редиректы не выполняются, любой HTTP-ответ считается успехом; задержка — время до ответа, предел 15 с; до 10 тестов параллельно; первый прогон — сразу после старта. У члена с включённым multiplex тест делается дважды (первый прогревает соединение). Неудачное соединение через выбранного члена стирает его результат.

Исходники: option/group.go, protocol/group/urltest.go, common/urltest/urltest.go, constant/timeout.go.

## Удалённые типы: dns, wireguard, shadowsocksr

| Тип | Что в 1.14.2 | Замена |
|---|---|---|
| `dns` | Ошибка разбора: `dns outbound is deprecated in sing-box 1.11.0 and removed in sing-box 1.13.0, use rule actions instead` (проверено). | Действие `hijack-dns` в правилах ([route.md](route.md)). |
| `wireguard` (исходящий) | Заглушка без полей (`StubOptions`). Только `type`/`tag` — разбор проходит, check: `WireGuard outbound is deprecated in sing-box 1.11.0 and removed in sing-box 1.13.0, use WireGuard endpoint instead`. Любое старое поле (`server`, `private_key`, …) — ошибка разбора `unknown field "server"`, до понятного сообщения дело не доходит (оба случая проверены). | Эндпоинт [wireguard](#эндпоинт-wireguard). |
| `shadowsocksr` | Заглушка, поля ниже ещё декодируются; check: `ShadowsocksR is deprecated and removed in sing-box 1.6.0` (проверено). Лишнее поле — ошибка разбора `unknown field` раньше этого сообщения (проверено). | Нет. |

Поля заглушки `shadowsocksr` (только разбираются, ничего не делают; создание всегда падает):

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `server`, `server_port` | string, int | — | Адрес и порт сервера (как у прочих исходящих). |
| `method` | string | — | Шифр SSR. |
| `password` | string | — | Пароль. |
| `obfs` | string | — | Обфускация SSR. |
| `obfs_param` | string | — | Параметр обфускации. |
| `protocol` | string | — | Протокол SSR. |
| `protocol_param` | string | — | Параметр протокола. |
| `network` | string\|[string] | обе | `tcp`/`udp`, см. [network](#поле-network). |
| dial-поля | — | — | [Dial-поля](shared.md#поля-подключения-dial). |

Входящий `shadowsocksr` декодируется полями входящего [shadowsocks](inbounds.md#shadowsocks) (поле `obfs` там — `unknown field`) и тоже падает при создании с тем же сообщением (проверено).

Подробнее — [deprecations.md](deprecations.md).

Исходники: option/outbound.go (`UnmarshalJSONContext`), include/registry.go (`registerStubForRemovedOutbounds`), option/shadowsocksr.go.

## Эндпоинт wireguard

с 1.11. WireGuard-интерфейс в пространстве пользователя (gVisor) или системный. Принимает и отправляет трафик, поддерживает L3-пересылку.

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `system` | bool | `false` | Создать системный интерфейс (нужны права; на Windows — адаптер через wintun). При `false` — сетевой стек gVisor. |
| `name` | string | автоматически | Имя системного интерфейса. |
| `mtu` | int | `1408` | MTU. |
| `address` | prefix\|[prefix] | — (обязательно по документации) | Адреса интерфейса (IPv4/IPv6). Без префикса — ошибка разбора; отсутствие поля check пропускает (проверено). |
| `private_key` | string | — (обязательно) | Закрытый ключ base64 (`sing-box generate wg-keypair`). Пустой — check `missing private key`; не base64 — `decode private key` (проверено). |
| `listen_port` | int | случайный | UDP-порт для входящих рукопожатий. Вместе с `detour` — check `` `listen_port` is conflict with `detour` `` (проверено). |
| `peers` | [object] | — (обязательно по документации) | Пиры. Пустой список check пропускает (проверено). |
| `peers[].address` | string | — | Адрес пира: IP или домен (домен резолвится при соединении через DNS sing-box). |
| `peers[].port` | int | — | Порт пира. |
| `peers[].public_key` | string | — (обязательно) | Открытый ключ пира base64. Не base64 — check; пустой check пропускает (проверено), по коду он уйдёт в конфигурацию wireguard-go при старте. |
| `peers[].pre_shared_key` | string | — | Общий ключ base64. |
| `peers[].allowed_ips` | prefix\|[prefix] | — (обязательно) | Разрешённые адреса пира; пустые — check `missing allowed ips for peer N` (проверено). |
| `peers[].persistent_keepalive_interval` | int | `0` (выключено) | Keepalive, секунды. |
| `peers[].reserved` | [int] или string base64 | — | Три зарезервированных байта (Cloudflare WARP): массив чисел или base64-строка (проверено `"AQID"`); длина не 3 — check `invalid reserved value`. |
| `udp_timeout` | duration | `5m` | Время жизни UDP-сессии NAT. Только строка: число — ошибка разбора (проверено; в отличие от listen-полей). |
| `udp_mapping` | string | `endpoint_independent` | с 1.14. [UDP NAT](shared.md#udp-nat): поведение отображения. |
| `udp_filtering` | string | `endpoint_independent` | с 1.14. Поведение фильтрации. |
| `udp_nat_max` | int | по объёму памяти | с 1.14. Предел числа UDP-сессий. |
| `workers` | int | число CPU | Число воркеров WireGuard. |
| dial-поля | — | — | [Dial-поля](shared.md#поля-подключения-dial) для UDP-пакетов к пирам. Поля бывшего исходящего wireguard (`server`, `local_address`, …) здесь неизвестны — ошибка разбора (проверено для `server`). |

Один пир с IP-адресом и без `listen_port` — «клиентский» режим с привязанным к пиру сокетом.

Исходники: option/wireguard.go, protocol/wireguard/endpoint.go, transport/wireguard/endpoint.go, transport/wireguard/device_*.go.

## Эндпоинт tailscale

с 1.12. Узел tailnet на встроенной библиотеке Tailscale (tsnet).

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `state_directory` | string | `tailscale` | Каталог состояния (раскрываются `$VAR`, относительный путь — от рабочего каталога). |
| `auth_key` | string | — | Ключ регистрации узла; не нужен, если узел уже зарегистрирован. Без него в журнал пишется ссылка для входа. |
| `control_url` | string | `https://controlplane.tailscale.com` | Сервер управления (например, Headscale). |
| `ephemeral` | bool | `false` | Регистрироваться как эфемерный узел. |
| `hostname` | string | имя системы, иначе `sing-box` | Имя узла; с 1.14 на iOS/tvOS/Android по умолчанию — имя устройства. |
| `accept_routes` | bool | `false` | Принимать маршруты, объявленные другими узлами. |
| `exit_node` | string | — | Имя или IP выходного узла. Вместе с `advertise_exit_node` — check `cannot advertise an exit node and use an exit node at the same time` (проверено). |
| `exit_node_allow_lan_access` | bool | `false` | Локальные подсети идут напрямую, а не через выходной узел. |
| `advertise_routes` | [prefix] | — | Объявлять эти подсети доступными через узел. Только массив (строка — ошибка разбора, проверено); маршрут по умолчанию (`0.0.0.0/0`) — check-ошибка, для этого есть `advertise_exit_node`. |
| `advertise_exit_node` | bool | `false` | Объявить себя выходным узлом. |
| `advertise_tags` | string\|[string] | — | с 1.13. Теги ACL узла (`tag:server`). |
| `listen_port` | int | автоматически | с 1.14. UDP-порт WireGuard/P2P. |
| `relay_server_port` | int | — | с 1.13. Порт для входящих ретранслируемых соединений других узлов. В коде тип-указатель: отсутствие поля и `0` различаются (смысл `0` не документирован). |
| `relay_server_static_endpoints` | [string] | — | с 1.13. Статические адреса `IP:порт` ретранслятора для объявления. |
| `system_interface` | bool | `false` | с 1.13. Создать системный TUN-интерфейс (на Windows — через wintun, нужны права). |
| `system_interface_name` | string | `tailscale` (`utun` на macOS) | с 1.13. Имя интерфейса. |
| `system_interface_mtu` | int | MTU Tailscale | с 1.13. MTU интерфейса. |
| `udp_timeout` | duration\|int | `5m` | Время жизни UDP-сессии; число — секунды (проверено). |
| `ssh_server` | bool\|object | выключен | с 1.14. SSH-сервер Tailscale на порту 22 tailnet; `true` = `{"enabled": true}`. На Windows в CLI сеансы идут от имени процесса sing-box, сопоставление с другим локальным пользователем отклоняется. |
| `ssh_server.enabled` | bool | `false` | Включить. |
| `ssh_server.disable_pty` | bool | `false` | Отказывать в PTY. |
| `ssh_server.disable_sftp` | bool | `false` | Отказывать в SFTP. |
| `ssh_server.disable_forwarding` | bool | `false` | Отказывать в пробросе TCP, unix-сокетов и агента. |
| `taildrop_directory` | string | `Taildrop` | с 1.14. Куда сохранять файлы Taildrop (относительный путь — от рабочего каталога). |
| dial-поля | — | — | [Dial-поля](shared.md#поля-подключения-dial). По документации влияют только на соединение с сервером управления; `detour` в граф зависимостей не входит (см. выше). |

DNS tailnet — через DNS-сервер типа `tailscale` ([dns.md](dns.md#сервер-tailscale)). Интерактивный вход — через панель sing-box или графический клиент.

Исходники: option/tailscale.go, protocol/tailscale/endpoint.go; документация: docs/configuration/endpoint/tailscale.md.

## Эндпоинт openconnect

с 1.14. Только клиент. Совместим с серверами Cisco AnyConnect, GlobalProtect, Fortinet, F5, Pulse Connect Secure и Juniper Network Connect. Собственный объект `tls` (не общий исходящий TLS). Проталкиваемые сервером DNS-настройки в систему не устанавливаются — их использует DNS-сервер типа `openconnect` ([dns.md](dns.md#серверы-openconnect-и-openvpn)).

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `system` | bool | `false` | Системный интерфейс (нужны права). При `false` — стек gVisor. |
| `name` | string | автоматически (`oc…`) | Имя системного интерфейса. |
| `udp_timeout` | duration | `5m` | [UDP NAT](shared.md#udp-nat): время жизни сессии (только строка по типу поля). |
| `udp_mapping` | string | `endpoint_independent` | UDP NAT: отображение. |
| `udp_filtering` | string | `endpoint_independent` | UDP NAT: фильтрация. |
| `udp_nat_max` | int | по объёму памяти | UDP NAT: предел сессий. |
| `server` | string | — (обязательно) | HTTPS-URL VPN-сервера; схема `https://` добавляется сама. userinfo, query и fragment не поддерживаются. Пустой — check `missing openconnect server` (проверено). |
| `flavor` | string | `anyconnect` | `anyconnect`, `gp`, `fortinet`, `f5`, `pulse`, `nc`; иное — check `unsupported openconnect flavor` (проверено). |
| `username` | string | — | Подставляется в подходящие поля формы входа. |
| `password` | string | — | То же для пароля. |
| `auth_group` | string | — | Группа/realm/домен/шлюз для предвыбора, если flavor поддерживает. |
| `cookie` | string | — | Готовая сессия (формат зависит от flavor: `webvpn`, строка запроса GP, `DSID`, cookie Pulse, `MRHSession`, `SVPNCOOKIE`). Отвергнутая сервером — обычный вход. |
| `token` | object | нет | Автоответ на поля токена или HTTP Bearer; нужен `secret` или `secret_path` (без них — check `software token requires a secret`, проверено). |
| `token.mode` | string | — (обязательно) | `totp`, `hotp`, `stoken` (RSA SecurID), `oidc` (Bearer-токен). |
| `token.secret` | string | — | Секрет: Base32, `base32:…` или `otpauth://` для OTP; содержимое CTF для `stoken`; токен доступа для `oidc`. Конфликтует с `secret_path`. |
| `token.secret_path` | string | — | Путь к файлу секрета. |
| `token.pin` | string | — | PIN для `stoken`. |
| `token.password` | string | — | Пароль зашифрованного токена `stoken`. |
| `token.device_id` | string | — | ID устройства для привязанного токена `stoken`. |
| `token.counter` | int | `0` | Начальный счётчик `hotp` (0 — из `otpauth://`, если есть). |
| `reported_os` | string | по платформе (`win` на Windows) | ОС, сообщаемая серверу: `linux`, `linux-64`, `win`, `mac-intel`, `android`, `apple-ios` (для anyconnect, gp, pulse). |
| `user_agent` | string | зависит от flavor | User-Agent клиента. |
| `version` | string | `v9.21` | Версия клиента (XML-вход AnyConnect). |
| `local_hostname` | string | имя системы или `localhost` | Сообщаемое имя хоста. |
| `mobile` | object | нет | Мобильная идентичность AnyConnect; если задан, нужны все три поля. |
| `mobile.platform_version` | string | — | Версия мобильной ОС. |
| `mobile.device_type` | string | — | Модель/тип устройства. |
| `mobile.device_unique_id` | string | — | Идентификатор устройства. |
| `csd` | object | встроенная обработка | Проверка соответствия CSD/host scan AnyConnect. |
| `csd.wrapper_path` | string | — | Внешний исполняемый файл-обёртка CSD (запускается программа). |
| `hip` | object | встроенный отчёт | HIP-отчёт GlobalProtect. |
| `hip.wrapper_path` | string | — | Внешняя программа HIP-отчёта. |
| `tncc` | object | встроенная обработка | Проверки TNCC Network Connect. |
| `tncc.wrapper_path` | string | — | Внешняя программа TNCC; конфликтует с остальными полями `tncc`. |
| `tncc.device_id` | string | — | ID устройства встроенного TNCC. |
| `tncc.user_agent` | string | `Neoteris HC Http` | User-Agent встроенного TNCC. |
| `tncc.machine_identification_enabled` | bool | `false` | Сообщать платформу, имя хоста и MAC-адреса. |
| `tncc.certificates` | [object] | — | Сертификаты машины для встроенного TNCC; требуют `machine_identification_enabled`. |
| `tncc.certificates[].certificate` | string\|[string] | — | PEM-содержимое; конфликтует с `certificate_path`. |
| `tncc.certificates[].certificate_path` | string | — | Путь к PEM. |
| `fortinet_host_check` | object | выключено | Подмена результата hostcheck Fortinet; включается непустым `hostcheck`. Ничего о системе не собирает. |
| `fortinet_host_check.hostcheck` | string | — | Строка результата, обычно `<статус>,<версия ОС>`. |
| `fortinet_host_check.check_virtual_desktop` | string | — | Результат проверки виртуального рабочего стола (MAC-адреса через `\|`). |
| `no_udp` | bool | `false` | Не поднимать канал DTLS/ESP, только TLS. |
| `dtls_local_port` | int | эфемерный | Локальный UDP-порт канала DTLS/ESP. |
| `compression_disabled` | bool | `false` | Не согласовывать сжатие AnyConnect. Вместе с `compression_mode: all` — check `compression_disabled conflicts with compression mode all` (проверено). |
| `compression_mode` | string | `stateless` | `stateless` (`oc-lz4`, `lzs`) или `all` (плюс `deflate` для CSTP). Сжатие ослабляет конфиденциальность. |
| `ipv6_disabled` | bool | `false` | Не запрашивать IPv6 в туннеле. |
| `http_keepalive_disabled` | bool | `false` | Не переиспользовать HTTP-соединения при входе. |
| `xml_post_disabled` | bool | `false` | Начинать вход AnyConnect со старого GET-потока. |
| `external_auth_disabled` | bool | `false` | Запретить внешний вход через браузер (SSO/SAML). |
| `password_authentication_disabled` | bool | `false` | Прерывать вход AnyConnect на форме с паролем (как `--no-passwd`). |
| `tcp_keep_alive_enabled` | bool | `false` | TCP keep-alive к серверу; конфликтует с dial `disable_tcp_keep_alive`; включается и заданием `tcp_keep_alive(_interval)`. |
| `pfs` | bool | `false` | Требовать шифры с forward secrecy для TLS 1.2 и ниже. |
| `mtu` | int | согласованный | Предпочтительный MTU туннеля; ненулевое меньше 576 считается 576, максимум 65535. |
| `base_mtu` | int | `1406` | Базовый MTU пути для расчёта MTU туннеля; меньше 1280 считается 1280. |
| `dpd_interval` | duration | от сервера или flavor | Интервал Dead Peer Detection; положительное меньше 2s считается 2s; отрицательное запрещено. |
| `reconnect_timeout` | duration | `300s` | Предел суммарной паузы между неудачными переподключениями. |
| `trojan_interval` | duration | от сервера (GP — `1h`) | Интервал HIP-отчётов GP или проверок TNCC. |
| `queue_length` | int | `32` | Длина очереди пакетов между транспортом и интерфейсом. |
| `allow_insecure_crypto` | bool | `false` | Разрешить слабые шифры и TLS 1.0 для старых серверов (проверку сертификата не выключает). |
| `tls` | object | — | TLS OpenConnect, поля ниже. |
| `tls.insecure` | bool | `false` | Не проверять сертификат и имя сервера. |
| `tls.server_name` | string | хост из `server` | SNI и имя для проверки. |
| `tls.peer_fingerprint` | string\|[string] | — | Допустимые отпечатки: SHA-1 сертификата (как `--servercert`), `sha1:<hex>`, `sha256:<hex>` (SPKI), `pin-sha256:<base64>`; допускается префикс от 4 символов. Совпадение может разрешить недоверенный сертификат. |
| `tls.system_trust_disabled` | bool | `false` | Не использовать системные корневые сертификаты. |
| `tls.certificate_authority` | string\|[string] | — | Дополнительные CA (PEM), добавляются к системным. |
| `tls.certificate_authority_path` | string | — | Путь к ним. |
| `tls.client_certificate` | string\|[string] | — | Клиентская цепочка PEM (вместе с ключом). |
| `tls.client_certificate_path` | string | — | Путь к ней. |
| `tls.client_key` | string\|[string] | — | Клиентский ключ PEM. |
| `tls.client_key_path` | string | — | Путь к ключу. |
| `tls.client_key_password` | string | — | Пароль зашифрованного ключа. |
| `tls.mca_certificate` | string\|[string] | — | Цепочка MCA (multiple-certificate authentication AnyConnect). |
| `tls.mca_certificate_path` | string | — | Путь к ней. |
| `tls.mca_key` | string\|[string] | — | Ключ MCA. |
| `tls.mca_key_path` | string | — | Путь к ключу MCA. |
| `tls.mca_key_password` | string | — | Пароль ключа MCA. |
| `form_entries` | [object] | — | Переопределения полей формы входа; сопоставление по `submission_key` или по паре `form_id` + `name`; более поздние записи важнее. |
| `form_entries[].form_id` | string | — | Идентификатор формы. |
| `form_entries[].submission_key` | string | — | Ключ отправки поля. |
| `form_entries[].name` | string | — | Имя поля. |
| `form_entries[].value` | string | — | Значение для автоподстановки; конфликтует с `promote`. |
| `form_entries[].promote` | bool | `false` | Спрашивать поле интерактивно. |
| dial-поля | — | — | [Dial-поля](shared.md#поля-подключения-dial). |

Исходники: option/openconnect.go, protocol/openconnect/client.go, protocol/openconnect/endpoint.go; документация: docs/configuration/endpoint/openconnect.md.

## Эндпоинт openvpn-client

с 1.14. Клиент OpenVPN (режимы TLS и static key). Совместим со стандартными серверами OpenVPN. Проталкиваемые маршруты и DNS в систему не устанавливаются: маршруты влияют только на выбор этого эндпоинта внутри sing-box, DNS используется через DNS-сервер типа `openvpn` ([dns.md](dns.md#серверы-openconnect-и-openvpn)). Большинство конфликтов полей (режим, `server`/`servers`, поля не своего режима) отвергает check.

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `system` | bool | `false` | Системный интерфейс (адреса и MTU; маршруты и DNS не ставятся). При `false` — стек gVisor. |
| `name` | string | автоматически (`ovpn…`) | Имя системного интерфейса. |
| `mtu` | int | `1500` до получения от сервера | MTU интерфейса. |
| `udp_mapping` | string | `endpoint_independent` | [UDP NAT](shared.md#udp-nat). |
| `udp_filtering` | string | `endpoint_independent` | UDP NAT. |
| `udp_nat_max` | int | по объёму памяти | UDP NAT. |
| `udp_timeout` | duration\|int | `5m` | UDP NAT: время жизни; число — секунды (проверено). |
| `mode` | string | `tls` | `tls` или `static_key` (устаревший режим без TLS и forward secrecy). |
| `server` | string | — | Адрес сервера; нужен `server` или `servers`. Оба — check `` `server` is conflict with `servers` `` (проверено). |
| `server_port` | int | — | Порт; обязателен при `server`. |
| `servers` | [object] | — | Серверы, перебираемые по порядку при сбоях. |
| `servers[].server` | string | — (обязательно) | Адрес. |
| `servers[].server_port` | int | — (обязательно) | Порт. |
| `servers[].network` | string | верхний `network` | Транспорт этого сервера. |
| `remote_random` | bool | `false` | Перемешать `servers` перед подключением. |
| `network` | string | `udp` | Транспорт: `udp`, `tcp` (код принимает и `udp4`, `udp6`, `tcp4`, `tcp6`). |
| `address` | prefix\|[prefix] | — | Адреса туннеля; в `static_key` обязательны (иначе check `` missing `address` in `static_key` mode ``, проверено), в TLS могут прийти от сервера. |
| `peer_address` | string (IPv4) | — | Адрес пира/шлюз IPv4; в `static_key` обязателен при IPv4-адресе. |
| `peer_address_ipv6` | string (IPv6) | — | То же для IPv6. |
| `topology` | string | от сервера (TLS) | `net30`, `p2p`, `subnet`. |
| `username` | string | — | Логин (только TLS). |
| `password` | string | — | Пароль. |
| `auth_retry` | string | `none` | `none` (сбой входа окончателен), `nointeract`, `interact`. |
| `static_challenge` | string | — | Текст статического запроса. |
| `static_challenge_echo` | bool | `false` | Показывать ответ открытым текстом. |
| `static_key` | string\|[string] | — | Статический ключ (обязателен в `static_key`); конфликтует с `static_key_path`. |
| `static_key_path` | string | — | Путь к ключу. |
| `key_direction` | string | двунаправленно | `server` или `client`; только в `static_key`. |
| `tls` | object | — (обязательно в TLS) | TLS управляющего канала, поля ниже. Нет — check `` missing `tls` options `` (проверено). |
| `tls.server_name` | string | — (не проверять имя) | Ожидаемое имя сертификата сервера. |
| `tls.server_name_type` | string | `name` | `subject`, `name`, `name-prefix`. |
| `tls.certificate` | string\|[string] | — | Доверенный CA; нужен `certificate`, `certificate_path` или `peer_fingerprint`. |
| `tls.certificate_path` | string | — | Путь к CA. |
| `tls.client_certificate` | string\|[string] | — | Клиентский сертификат (вместе с ключом). |
| `tls.client_certificate_path` | string | — | Путь к нему. |
| `tls.client_key` | string\|[string] | — | Клиентский ключ. |
| `tls.client_key_path` | string | — | Путь к ключу. |
| `tls.peer_fingerprint` | string\|[string] | — | SHA-256 листового сертификата сервера: 64 строчных hex-символа без разделителей. Без CA цепочка не проверяется. |
| `tls.crl_path` | string | — | CRL (PEM или DER) для отзыва сертификатов сервера. |
| `tls.remote_certificate_ku` | string\|[string] | — | Требуемые маски key usage (hex, как `remote-cert-ku`). |
| `tls.remote_certificate_eku` | string | — | Требуемый extended key usage; конфликтует с явным `remote_certificate_tls`. |
| `tls.remote_certificate_tls` | string | `server` | Проверка назначения сертификата: `server`, `client`, `none`. |
| `tls.certificate_profile` | string | `legacy` | `insecure`, `legacy`, `preferred`, `suiteb`. |
| `tls.ns_certificate_type` | string | выключено | Устаревшая проверка Netscape: `server`, `client`. |
| `tls.version_min` | string | `1.2` | `1.0`–`1.3`. |
| `tls.version_max` | string | максимальная | `1.0`–`1.3`, не ниже `version_min`. |
| `tls.cipher` | string | умолчания | Шифры TLS 1.2 и ниже через `:` (имена OpenSSL). |
| `tls.groups` | string | умолчания | Группы обмена ключами через `:` (`X25519`, `SECP256R1`, `SECP384R1`, `SECP521R1`). |
| `tls.control_wrap` | object | выключено | Обёртка управляющего канала (`tls-auth`, `tls-crypt`, `tls-crypt-v2`). |
| `tls.control_wrap.type` | string | — | `tls_auth`, `tls_crypt`, `tls_crypt_v2`. |
| `tls.control_wrap.key` | string\|[string] | — | Ключ обёртки; конфликтует с `key_path`. |
| `tls.control_wrap.key_path` | string | — | Путь к ключу. |
| `tls.control_wrap.direction` | string | двунаправленно | `server`/`client`, только для `tls_auth`. |
| `cipher` | string | `BF-CBC` | Шифр данных только в `static_key` (в TLS — check-ошибка). |
| `data_ciphers` | string\|[string] | `AES-256-GCM`, `AES-128-GCM`, `CHACHA20-POLY1305` | Допустимые шифры канала данных (только TLS). |
| `data_ciphers_fallback` | string | выключено | Шифр для пиров без согласования (только TLS). |
| `auth` | string | `SHA1` | Дайджест для не-AEAD шифров и `tls_auth`. |
| `mss_fix` | int | как в OpenVPN (`1492` или `fragment`) | Предельный размер UDP-пакета для ограничения MSS. |
| `mss_fix_disabled` | bool | `false` | Выключить ограничение MSS; конфликтует с `mss_fix`, `mss_fix_mode`. |
| `mss_fix_mode` | string | обычный расчёт | `mtu` или `fixed`; требует `mss_fix`. |
| `fragment` | int | `0` (выключено) | Фрагментация канала данных; не меньше 68; с TCP — check `option is not supported yet: fragment with tcp remote` (проверено). |
| `replay_window` | int | `64` | Окно защиты от повтора UDP (до 65536). |
| `replay_window_time` | duration | `15s` | Длительность окна (целые секунды, до `10m`). |
| `compression` | string | выключено | Кадрирование `compress`: `none`, `no`, `lz4`, `lz4-v2`, `stub`, `stub-v2`, `disabled`, `off`. |
| `compression_lzo` | string | выключено | `comp-lzo`: `none`, `no`, `yes`, `adaptive`, `asym`, `disabled`, `off`. |
| `allow_compression` | string | `no` | Политика сжатия от сервера: `no`, `asym`, `yes` (= `asym`). |
| `route_no_pull` | bool | `false` | Игнорировать проталкиваемые маршруты, DNS, `redirect-gateway` и т. п. |
| `pull_filters` | [object] | — | Фильтры проталкиваемых опций; применяется первый, чей `text` — префикс опции. |
| `pull_filters[].action` | string | — (обязательно) | `accept`, `ignore`, `reject` (разрыв соединения). |
| `pull_filters[].text` | string | — (обязательно) | Префикс с учётом регистра. |
| `routes` | prefix\|[prefix] | — | Дополнительные префиксы, для которых sing-box предпочитает этот эндпоинт (системные маршруты не ставятся). |
| `route_gateway` | string (IPv4) | от сервера | Шлюз; только для совместимости. |
| `route_metric` | int | `0` | Метрика; только для совместимости. |
| `redirect_gateway` | bool | `false` | Предпочитать эндпоинт для всех IPv4 внутри sing-box. |
| `redirect_gateway_flags` | string\|[string] | — | Флаги `redirect-gateway` (`!ipv4`, `def1`, `ipv6`, …; `block-local` не поддерживается). |
| `redirect_private` | bool | `false` | Принять флаги без предпочтения маршрута по умолчанию. |
| `block_ipv6` | bool | `false` | Отвергать IPv6 локально. |
| `ping_interval` | duration | выключено | Пинг канала данных (целые секунды; значение сервера важнее). |
| `ping_restart` | duration | `120s` для UDP с pull | Переподключение при тишине (целые секунды). |
| `ping_restart_disabled` | bool | `false` | Выключить этот тайм-аут; конфликтует с `ping_restart`. |
| `renegotiate_interval` | duration | `1h` | Период пересогласования TLS. |
| `renegotiate_disabled` | bool | `false` | Выключить пересогласование по времени. |
| `renegotiate_bytes` | int | по шифру | Пересогласовать ключи после N байт. |
| `renegotiate_packets` | int | по шифру | После N пакетов. |
| `tls_timeout` | duration | `2s` | Начальный тайм-аут повтора управляющих пакетов. |
| `handshake_window` | duration | `1m` | Предел рукопожатия и каждого пересогласования. |
| `explicit_exit_notify` | int | `0` | Сколько уведомлений о выходе послать при закрытии UDP. |
| dial-поля | — | — | [Dial-поля](shared.md#поля-подключения-dial). |

Исходники: option/openvpn.go (`OpenVPNClientEndpointOptions`, `OpenVPNOutboundTLSOptions`, `OpenVPNControlWrapOptions`, `OpenVPNRemoteOptions`, `OpenVPNPullFilterOptions`), protocol/openvpn/client.go, protocol/openvpn/endpoint.go; документация: docs/configuration/endpoint/openvpn-client.md.

## Эндпоинт openvpn-server

с 1.14. Сервер OpenVPN, совместимый со стандартными клиентами. Слушает по [listen-полям](shared.md#поля-прослушивания-listen) (`listen`, `listen_port`, `udp_timeout` и др.); один эндпоинт обслуживает один транспорт.

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| listen-поля | — | — | [Listen-поля](shared.md#поля-прослушивания-listen). |
| `system` | bool | `false` | Системный интерфейс (адреса и MTU). |
| `name` | string | автоматически (`ovpn…`) | Имя интерфейса. |
| `mtu` | int | `1500` | MTU интерфейса. |
| `udp_mapping` | string | `endpoint_independent` | [UDP NAT](shared.md#udp-nat). |
| `udp_filtering` | string | `endpoint_independent` | UDP NAT. |
| `udp_nat_max` | int | по объёму памяти | UDP NAT. |
| `mode` | string | `tls` | `tls` или `static_key` (один пир). |
| `network` | string | `udp` | `udp` или `tcp`. |
| `remote` | string | — | Фиксированный адрес пира для UDP `static_key` (обязателен там вместе с `remote_port`). |
| `remote_port` | int | — | Порт пира. |
| `max_clients` | int | `1024` | Предел сессий (меньше 16777216; в `static_key` — 0 или 1). |
| `address` | prefix\|[prefix] | — (обязательно) | Не более одного IPv4- и одного IPv6-префикса: адрес сервера и пул клиентов. |
| `peer_address` | string (IPv4) | — | Адрес пира в `static_key`. |
| `peer_address_ipv6` | string (IPv6) | — | То же для IPv6. |
| `topology` | string | `subnet` (TLS), `p2p` (`static_key`) | Проталкиваемая топология. |
| `duplicate_cn` | bool | `false` | Разрешить несколько сессий с одним CN/логином. |
| `users` | [object] | — | Пары `{"username", "password"}`; проверяются вдобавок к политике сертификатов (только TLS). |
| `static_key` | string\|[string] | — | Статический ключ (`static_key`). |
| `static_key_path` | string | — | Путь к нему. |
| `key_direction` | string | двунаправленно | `server`/`client`, только `static_key`. |
| `tls` | object | — (обязательно в TLS) | Поля ниже. Без сертификата — check `` missing `tls.certificate` or `tls.certificate_path` `` (проверено). |
| `tls.certificate` | string\|[string] | — | Сертификат сервера (или `certificate_path`). |
| `tls.certificate_path` | string | — | Путь к нему. |
| `tls.key` | string\|[string] | — | Ключ сервера (или `key_path`). |
| `tls.key_path` | string | — | Путь к ключу. |
| `tls.client_certificate` | string\|[string] | — | CA для проверки клиентов. |
| `tls.client_certificate_path` | string | — | Путь к CA. |
| `tls.verify_client_certificate` | string | `require` | `require`, `optional`, `none`. |
| `tls.client_name` | string | — | Ожидаемое имя клиентского сертификата. |
| `tls.client_name_type` | string | `name` | `subject`, `name`, `name-prefix`. |
| `tls.peer_fingerprint` | string\|[string] | — | SHA-256 клиентских сертификатов (можно без CA). |
| `tls.crl_path` | string | — | CRL для клиентских сертификатов. |
| `tls.remote_certificate_ku` | string\|[string] | — | Требуемые маски key usage. |
| `tls.remote_certificate_eku` | string | — | Требуемый EKU; конфликтует с явным `remote_certificate_tls`. |
| `tls.remote_certificate_tls` | string | `client` | `server`, `client`, `none`. |
| `tls.certificate_profile` | string | `legacy` | `insecure`, `legacy`, `preferred`, `suiteb`. |
| `tls.ns_certificate_type` | string | — | Устаревшая проверка Netscape. |
| `tls.version_min` | string | `1.2` | Минимальная версия TLS. |
| `tls.version_max` | string | максимальная | Максимальная версия TLS. |
| `tls.cipher` | string | умолчания | Шифры TLS 1.2 и ниже. |
| `tls.groups` | string | умолчания | Группы обмена ключами. |
| `tls.control_wrap` | object | выключено | Обёртка управляющего канала. |
| `tls.control_wrap.type` | string | — (обязательно) | `tls_auth`, `tls_crypt`, `tls_crypt_v2` (для v2 — ключ сервера). |
| `tls.control_wrap.key` | string\|[string] | — | Ключ (или `key_path`). |
| `tls.control_wrap.key_path` | string | — | Путь к ключу. |
| `tls.control_wrap.direction` | string | двунаправленно | Только `tls_auth`: `server` (0) или `client` (1). |
| `tls.control_wrap.force_cookie` | bool | `false` | Только `tls_crypt_v2`: требовать от UDP-клиентов поддержку cookie. |
| `cipher` | string | `BF-CBC` | Шифр данных в `static_key`. |
| `data_ciphers` | string\|[string] | `AES-256-GCM`, `AES-128-GCM`, `CHACHA20-POLY1305` | Шифры канала данных (TLS). |
| `data_ciphers_fallback` | string | выключено | Шифр для клиентов без согласования. |
| `auth` | string | `SHA1` | Дайджест для не-AEAD и `tls_auth`. |
| `mss_fix` | int | как в OpenVPN | Ограничение MSS. |
| `mss_fix_disabled` | bool | `false` | Выключить ограничение MSS. |
| `mss_fix_mode` | string | обычный расчёт | `mtu` или `fixed`; требует `mss_fix`. |
| `replay_window` | int | `64` | Окно защиты от повтора UDP. |
| `replay_window_time` | duration | `15s` | Длительность окна (целые секунды). |
| `push` | object | — | Что проталкивать клиентам, поля ниже. |
| `push.routes` | prefix\|[prefix] | — | Маршруты. |
| `push.dns` | string\|[string] (IP) | — | DNS-серверы старым `dhcp-option DNS/DNS6`. |
| `push.dns_servers` | [object] | — | Современные группы DNS (директива `dns server`). Клиент применяет только группу с наименьшим `priority`. Поля элемента — ниже. |
| `push.dns_servers[].priority` | int | `0` | Приоритет группы, меньше — важнее. Отсутствие кодом не проверяется (остаётся `0`). |
| `push.dns_servers[].addresses` | string\|[string] | — | IP или `IP:порт` (IPv6 с портом — `[IPv6]:порт`). Не адрес или порт `0` — ошибка создания `invalid push.dns_servers[N].addresses[M]` (по коду, ловит check). Пустой список кодом не отвергается. |
| `push.dns_servers[].resolve_domains` | string\|[string] | — | Домены, для которых предназначена группа. |
| `push.dns_servers[].dnssec` | string | — | `yes`, `optional`, `no` (перечень из документации и enum схемы; в коде sing-box значение не проверяется). |
| `push.dns_servers[].transport` | string | — | `plain`, `dot`, `doh` (то же замечание). |
| `push.dns_servers[].sni` | string | — | Имя сервера для `dot`/`doh`. |
| `push.search_domains` | string\|[string] | — | Домены поиска. |
| `push.dhcp_options` | string\|[string] | — | Дополнительные `dhcp-option` без префикса. |
| `push.redirect_gateway` | bool | `false` | Проталкивать `redirect-gateway`. |
| `push.redirect_gateway_flags` | string\|[string] | `def1` | Флаги к нему. |
| `push.block_outside_dns` | bool | `false` | Проталкивать `block-outside-dns` (действует у клиентов Windows). |
| `push.ping_interval` | duration | выключено | `ping` для клиентов (целые секунды). |
| `push.ping_restart` | duration | выключено | `ping-restart` для клиентов. |
| `ping_interval` | duration | выключено | Пинг от сервера к клиенту. |
| `ping_restart` | duration | выключено | Закрыть сессию клиента после тишины; должен быть больше клиентского. |
| `renegotiate_interval` | duration | `1h` | Период пересогласования (TLS). |
| `renegotiate_disabled` | bool | `false` | Выключить его. |
| `renegotiate_bytes` | int | по шифру | Порог байт. |
| `renegotiate_packets` | int | по шифру | Порог пакетов. |
| `handshake_window` | duration | `1m` | Предел рукопожатия (TLS). |

Dial-полей нет, зависимостей для графа старта тоже.

Исходники: option/openvpn.go (`OpenVPNServerEndpointOptions`, `OpenVPNInboundTLSOptions`, `OpenVPNInboundControlWrapOptions`, `OpenVPNPushOptions`, `OpenVPNPushDNSServerOptions`), protocol/openvpn/server.go; документация: docs/configuration/endpoint/openvpn-server.md.

## Что ловит check, а что всплывает позже

Сводка по этому файлу (проверено на `sing-box.exe` 1.14.2 для Windows, если не сказано иное).

| Ситуация | check | Когда проявится |
|---|---|---|
| `"Type"`/`"Tag"` не строчными, неизвестное поле, неверный тип, неизвестный `type` | ошибка разбора | — |
| дубликат тега среди исходящих и эндпоинтов (в том числе подставленных номеров) | ошибка разбора | — |
| удалённые `dns`, `wireguard`-исходящий, `shadowsocksr`, `override_*`, `proxy_protocol` у direct | ошибка | — |
| `detour` у `direct` | ошибка | — |
| нет `tls.enabled` у hysteria, hysteria2, tuic, shadowtls, anytls, naive | ошибка `TLS required` | — |
| неизвестные `method`, `security`, `flow`, `packet_encoding`, `version`, `congestion_control`, `bbr_profile`, `obfs.type`, flavor | ошибка | — |
| неверный диапазон `server_ports`, неверный base64 ключей | ошибка | — |
| `naive` без `libcronet.dll` | ошибка | — |
| `ssh` без файла `private_key_path` | ошибка | — |
| группа без членов | ошибка `missing tags` | — |
| `domain_resolver` на несуществующий DNS-сервер при доменном `server` | ошибка | — |
| `realm.http_client` на несуществующий тег | ошибка | — |
| `detour`/член группы на несуществующий тег, кольцо | проходит | при старте |
| `default` selector вне `outbounds` | проходит | при старте (если в `cache_file` нет сохранённого выбора) |
| `interval` urltest больше `idle_timeout` | проходит | при старте |
| `bridge` без прав администратора | проходит | при старте |
| `tor` без исполняемого файла | проходит | при старте |
| `detour` на «пустой» direct | проходит | при первом соединении |
| пустые `server`, `password`, `uuid` (vmess/vless), `realm_id`, короткий `psk` v6, пустой `public_key` пира | проходит | при старте или подключении |
| неверный `url` urltest, неизвестный `udp_relay_mode` tuic | проходит | тесты не проходят / молча `native` |
| несовместимые сочетания (vision без TLS, UoT с multiplex) | проходит | поведение библиотеки |
| `hop_interval` < `5s`, `hop_interval_max` < `hop_interval` или без `hop_interval` (hysteria/hysteria2 с `server_ports`) | проходит | при подключении (ошибка sing-quic, по коду) |

## Заметки для tray-sing-box

- Защита конфига (`internal/infrastructure/configfile/guard.go`) пропускает типы исходящих `direct`, `block`, `dns`, `selector`, `urltest`, `socks`, `http`, `shadowsocks`, `vmess`, `vless`, `trojan`, `naive`, `hysteria`, `hysteria2`, `tuic`, `wireguard`, `shadowtls`, `ssh`, `anytls` и эндпоинт `wireguard`. Из них `dns` и исходящий `wireguard` в 1.14.2 удалены (их отвергает сам check). Типы 1.14 `snell` и `bridge` в списке отсутствуют: импортёр Snell и так не производит (нет ни разбора ссылок, ни этого типа в списке типов профилей sing-box), а добавить его через приложение защита не даст; `bridge` требует прав и драйвера WinDivert, так что его отсутствие оправдано. `tor` исключён правильно: он запускает внешнюю программу.
- `naive` работает только при `libcronet.dll` рядом с `sing-box.exe`: без неё check отвергает весь конфиг с naive-узлом. Обновление sing-box в приложении ставит DLL релиза рядом с `sing-box.exe` (`internal/infrastructure/updater`).
- `ssh.private_key_path`, `tor.data_directory`, `tailscale.state_directory`/`taildrop_directory` раскрывают `$VAR` из окружения процесса sing-box; у OpenConnect `csd`/`hip`/`tncc.wrapper_path` запускают внешние программы. Защита отвергает все `*_path`/`*_directory`, а эндпоинты, кроме wireguard, не пропускает.
- Ошибки графа зависимостей (отсутствующий `detour`/член группы, кольцо), `default` selector вне членов и `route.final` проявляются только при старте — это то, что повторяют `dependency.go` и `checkSelectorDefaults`. Не повторяются там (на момент написания): `interval` > `idle_timeout` у urltest (падение при старте) и `detour` на «пустой» direct (ошибка при каждом соединении через такой узел).
- `foldKey` проекта считает `"Tag"` тегом, а sing-box такой ключ отвергает при разборе (как и `"Type"`); расхождение безвредно: такой конфиг не пройдёт check.
- vmess/vless не проверяют `uuid` в check: опечатка в UUID при импорте не будет поймана проверкой — строка молча станет другим UUID (UUIDv5 от неё), и сервер такого пользователя не узнает.

## Расхождения документации и кода

1. `type`/`tag`: у всех прочих ключей регистр не важен, а у этих двух — важен (разбор падает на `"Type"`/`"Tag"`); в документации не описано.
2. `block`: документация (deprecated.md, значок в outbound/block.md) говорит об устаревании в 1.11 и удалении в 1.13; в 1.14.2 тип зарегистрирован и работает без предупреждений. Changelog 1.11.10 («Undeprecate the `block` outbound») с кодом согласен, deprecated.md и страница типа — нет.
3. `direct`: страница всё ещё обещает удаление `override_*` «в 1.13», хотя они уже удалены; там же осталась строка «Protocol value can be 1 or 2» от удалённого `proxy_protocol`. Схема (schema.json) перечисляет `detour` у direct, код его запрещает.
4. vmess `security`: документация называет устаревшим методом `aes-128-ctr`, код его отвергает и принимает `aes-128-cfb`.
5. hysteria v1, устаревшие поля: документация советует заменить `recv_window_conn` на `stream_receive_window` и `recv_window` на `connection_receive_window`; код переносит наоборот (`recv_window_conn` → `connection_receive_window`, `recv_window` → `stream_receive_window`). По исходной семантике Hysteria права документация — похоже на ошибку в коде (не проверено запуском). Заметки устаревания в `experimental/deprecated` для них нет, предупреждение не выводится.
6. hysteria v1 `up`/`down`: единица `bps` из документации отвергается (`unsupported unit`); число без кавычек принимается (байты/с), формы без `ps` (`MB`, `Mb`, `B`, `b`, `KiB` и др.) тоже — в документации этого нет. По исходнику библиотеки sing (`NetworkBytesCompat`) такие формы — объём в байтах без учёта регистра, так что `"100 Mb"` = 100 МБ/с, а не 100 Мбит/с.
7. hysteria v1 `server_ports` «конфликтует с `server_port`» — check пропускает оба.
8. hysteria2 `obfs.min_packet_size`/`max_packet_size` при `salamander` и любые лишние ключи в таком `obfs` молча игнорируются, хотя везде неизвестный ключ — ошибка.
9. hysteria2 `realm.realm_id` и `realm.stun_servers` помечены обязательными, check их отсутствие пропускает.
10. snell: `obfs_mode` в документации — `none`/`http`, код принимает и `tls`; требование длины `psk` 12–255 для v6 check не проверяет.
11. tuic: `zero_rtt_handshake` и `heartbeat` есть в структуре документации исходящего, но не описаны; неизвестный `udp_relay_mode` молча принимается.
12. shadowsocks: «`udp_over_tcp` конфликтует с `multiplex`» — ошибки нет, multiplex молча выключается.
13. tor: пример `"torrc": {"ClientOnly": 1}` не разбирается (значения — только строки); тег `with_embedded_tor` описан в документации сборки, но в коде 1.14.2 встроенного Tor нет.
14. trojan `password`, anytls `password`, shadowtls `password` (v2/v3), `server` у всех типов помечены обязательными, но check их не требует.
15. wireguard-эндпоинт: `address`, `peers`, `peers[].public_key` помечены обязательными, check пропускает их отсутствие; `listen_port` есть в структуре, но не описан; `udp_timeout` не принимает число, хотя у listen-полей и tailscale/openvpn-client принимает.
16. openvpn-client `network`: документация — `udp`/`tcp`, код (enum) принимает и `udp4`/`udp6`/`tcp4`/`tcp6`.
17. anytls `client_metadata` помечен «с 1.13.16» — ветку 1.13 по дереву не проверить.

Неуверенности: алгоритм `security: auto` без TLS; поведение при старте для пустого `public_key` пира WireGuard; смысл `relay_server_port: 0` у tailscale; что `dial`-поля tailscale действуют только на сервер управления (по коду тот же диалер отдан tsnet целиком — утверждение взято из документации).
