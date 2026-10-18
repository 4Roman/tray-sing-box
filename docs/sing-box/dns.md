# DNS: секция `dns` (sing-box 1.14.2)

Справочник по секции `dns`: общие параметры, все типы DNS-серверов, DNS-правила и их действия, два режима работы правил, FakeIP, а также то, что отсекает `sing-box check`, и то, что проявляется только при запуске. Источник истины — код тега `v1.14.2`; там, где документация апстрима с ним расходится, прав код (сводка расхождений — в конце файла). Поведение проверялось командой `sing-box.exe check` из официальной сборки 1.14.2 для Windows amd64 (теги `with_quic`, `with_dhcp`, `with_utls`, `with_tailscale`, `with_openvpn`, `with_openconnect` и др.; CGO выключен).

Смежные файлы: загрузка конфига и регистр ключей в целом — [config.md](config.md); Dial Fields, TLS, объект `domain_resolver` — [shared.md](shared.md); правила маршрутизации, действия `hijack-dns` и `resolve`, `route.default_domain_resolver`, описание rule-set — [route.md](route.md); DNS у TUN (`dns_mode`, `strict_route`) — [inbounds.md](inbounds.md); исходящие — [outbounds.md](outbounds.md); `cache_file` (`store_dns`, `store_rdrc`, `store_fakeip`) и Clash API (`clash_mode`) — [experimental.md](experimental.md); общий список устаревшего — [deprecations.md](deprecations.md); команды CLI — [cli.md](cli.md).

Обозначения типов: `string`, `int`, `bool`, `duration` (синтаксис Go: `"10s"`, `"1m30s"`; по проверке принимается и суффикс дней `"1d"`), `string|[string]` — одно значение или массив (badoption.Listable), `object`, `[object]`, `-> dns server` / `-> outbound` / `-> endpoint` / `-> rule-set` — ссылка по тегу.

## Как sing-box обрабатывает DNS

- Запросы попадают в DNS-маршрутизатор двумя путями. «Клиентские» — DNS-пакеты, которые маршрут перехватил действием `hijack-dns` (обычно трафик из TUN), см. [route.md](route.md). «Внутренние» — разрешение имён самим sing-box: действие `resolve` без `server`, direct-исходящий с доменом назначения, эндпоинты WireGuard/Tailscale в роли исходящего, SOCKS4-исходящий, DERP `bootstrap-dns`, служба `resolved`.
- Если запрос адресован конкретному серверу — `domain_resolver` в Dial Fields, `route.default_domain_resolver`, `server` в действии `resolve` — DNS-правила не применяются: запрос сразу уходит в этот сервер.
- Иначе правила `dns.rules` просматриваются по порядку. Конечные действия (`route`, `respond`, `reject`, `predefined`) завершают перебор; `evaluate` и `route-options` — нет. Если конечного действия не нашлось, запрос обслуживает сервер по умолчанию (`dns.final`, иначе первый сервер списка).
- Ответы кэширует общий DNS-клиент; ключ кэша включает тег сервера, поэтому ответы разных серверов не смешиваются.
- Запрос с числом вопросов, отличным от одного, получает FORMERR. SVCB-запрос к `_dns.*` (обнаружение резолвера, DDR) получает пустой NOERROR без обращения к серверам.
- Без секции `dns` или с пустым `servers` при запуске создаётся неявный сервер типа `local` с тегом `local`.

Исходники: box.go, dns/router.go, dns/client.go, dns/transport_manager.go.

## Верхний уровень `dns`

Секция задаёт список серверов, правила и общие параметры DNS-клиента (кэш, стратегия, тайм-аут, ECS).

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `servers` | [object] | `[]` | DNS-серверы, см. [DNS-серверы](#dns-серверы-общие-поля-и-сводка-типов). |
| `rules` | [object] | `[]` | DNS-правила, см. [DNS-правила](#dns-правила). |
| `final` | string -> dns server | первый сервер | Сервер по умолчанию. Пусто — первый элемент `servers`; если он `fakeip`, `check` падает (`default server cannot be fakeip`). Указание `fakeip` здесь — та же ошибка. Несуществующий тег `check` пропускает, а запуск падает: `default DNS server not found: X`. |
| `strategy` | string | `""` | Стратегия по умолчанию: `prefer_ipv4`, `prefer_ipv6`, `ipv4_only`, `ipv6_only`; `""` или `as_is` — без ограничений. Для внутренних разрешений определяет, какие семейства запрашивать и в каком порядке отдавать адреса. Для клиентских запросов при `ipv4_only` запрос AAAA получает пустой NOERROR (и наоборот), а из записей HTTPS вырезаются подсказки чужого семейства. Перекрывается стратегией конкретного запроса (`domain_resolver.strategy`, `resolve.strategy`). |
| `disable_cache` | bool | `false` | Не кэшировать ответы. Несовместимо с `optimistic` (ошибка `check`). |
| `disable_expire` | bool | `false` | Записи кэша не истекают по TTL. Несовместимо с `optimistic` (ошибка `check`). |
| `independent_cache` | bool | `false` | Устарело в 1.14, удаление в 1.16. Ничего не делает (кэш и так разделён по тегу сервера), при `true` в лог пишется предупреждение. |
| `cache_capacity` | int | `1024` | С 1.11. Ёмкость LRU-кэша; значение меньше 1024 заменяется на 1024. |
| `optimistic` | bool\|object | `false` | С 1.14. Оптимистичный кэш: истёкший ответ отдаётся сразу (с TTL 1), а обновление идёт в фоне. `true` — окно 3 суток; объект — см. ниже. Несовместимо с `disable_cache` и `disable_expire`. |
| `timeout` | duration | `"10s"` | С 1.14. Тайм-аут одного DNS-запроса. Перекрывается полем `timeout` действия правила и `domain_resolver.timeout`. |
| `reverse_mapping` | bool | `false` | Запоминать соответствие IP -> домен из ответов (LRU на 1024 записи, срок жизни = TTL), чтобы маршрутизация знала домен соединения по IP назначения. Ответы `fakeip` не запоминаются. Работает только если приложение само резолвит имя через sing-box до соединения. |
| `client_subnet` | string | — | Префикс EDNS Client Subnet (ECS), добавляемый к каждому запросу; IP без маски превращается в `/32` или `/128`. Перекрывается `client_subnet` действия правила и `domain_resolver.client_subnet`; `remove_client_subnet` в действии его подавляет. |
| `fakeip` | object | — | Удалено в 1.14: сам ключ — ошибка разбора (`legacy DNS fakeip options are deprecated in sing-box 1.12.0 and removed in sing-box 1.14.0`). Заменено сервером `"type": "fakeip"`. |

Объект `optimistic`:

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `enabled` | bool | `false` | Включить оптимистичный кэш. |
| `timeout` | duration | `"3d"` | Сколько после истечения TTL ещё можно отдавать устаревший ответ. |

Особенности кэша (по коду): ключ — вопрос + тег сервера + ECS + «окружение» сервера (для `local`, `dhcp`, `mdns`, `resolved` это набор системных DNS-серверов, так что после смены сети старые ответы не используются). Не кэшируются «непростые» запросы (больше одного вопроса, записи в NS, в Extra что-то кроме OPT с ECS) и все ответы `fakeip`. При `experimental.cache_file.store_dns` кэш хранится в файле кэша вместо памяти ([experimental.md](experimental.md)).

Исходники: option/dns.go (RawDNSOptions, DNSClientOptions, OptimisticDNSOptions), dns/router.go (NewRouter), dns/client.go, constant/timeout.go (DNSTimeout), experimental/deprecated/constants.go.

## Ключи и неизвестные поля внутри `dns`

Общие правила декодера описаны в [config.md](config.md); здесь — то, что проверено на секции `dns` командой `check` 1.14.2.

- Неизвестный ключ — ошибка разбора (`json: unknown field "X"`), в том числе ключи старого формата (`address_resolver` у нового сервера) и поле не своего типа (`tls` у `udp`, `path` у `udp`).
- Исключение: параметры действий `reject` и `route-options` разбираются нестрого — лишние ключи молча отбрасываются (`{"action": "reject", "server": "x"}` проходит, `server` теряется; видно в выводе `sing-box format`).
- Пустые объекты `{}` выбрасываются ещё до разбора: `"tls": {}` у `udp` не ошибка, правило `{}` в `rules` просто исчезает (а внутри логического правила оставляет пустой список -> `missing conditions`).
- Регистр ключей учитывается не везде одинаково:
  - без учёта регистра: поля самой секции (`DNS`, `Servers`, `Rules`, `Final`, `Strategy`, `Cache_Capacity`, `Optimistic` с вложенными полями проходят), параметры сервера (`Server`, `Server_Port`, `Detour`, `Domain_Resolver`), параметры действия (`Server`, `Tag` у `evaluate`, `Rcode`);
  - строго в нижнем регистре (иначе `unknown field`): `type` и `tag` сервера; все условия DNS-правила (`domain_suffix`, `invert`, `match_response`, …); `type`, `mode`, `rules`, `invert` логического правила; `action` и `race` у действий с параметрами (`route`, `evaluate`, `reject`, …; у `respond`, где параметров нет, `Race` проходит).
  Объяснение (выведено из поведения, исходник декодера `github.com/sagernet/sing/common/json/badjson` в дерево не входит): такие объекты разбираются в два этапа, и ключи первого этапа исключаются из остатка по точному имени, а остаток разбирается со строгой проверкой неизвестных полей.

Исходники: option/dns.go (DNSServerOptions.UnmarshalJSONContext), option/rule_dns.go (DefaultDNSRule/LogicalDNSRule.UnmarshalJSONContext), option/rule_action.go (DNSRuleAction, RejectActionOptions, DNSRouteOptionsActionOptions).

## DNS-серверы: общие поля и сводка типов

Каждый элемент `servers` — объект с `type`, `tag` и полями своего типа. С 1.12 это единственный поддерживаемый формат ([старый формат удалён](#устаревший-формат-серверов-и-миграция)).

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `type` | string | — (обязательно) | Тип сервера (таблица ниже). Пустой или `legacy` — ошибка разбора (legacy-формат удалён в 1.14); неизвестный — `unknown transport type: X`. |
| `tag` | string | индекс в списке (`"0"`, `"1"`, …) | Имя для ссылок из `final`, правил, `domain_resolver`, `preferred_by`. Дубликаты не проверяются: `check` проходит, а более поздний сервер с тем же тегом молча заменяет ранний. |

| `type` | С версии | Собственные поля | Dial Fields | `tls` | `preferred_by` | Windows (официальная сборка) |
|---|---|---|---|---|---|---|
| `local` | 1.12 | `prefer_go`, `neighbor_domain` | да | — | да | да, [особое поведение](#сервер-local) |
| `hosts` | 1.12 | `path`, `predefined` | — | — | да | да |
| `udp` | 1.12 | `server`, `server_port` | да | — | — | да |
| `tcp` | 1.12 | `server`, `server_port` | да | — | — | да |
| `tls` | 1.12 | `server`, `server_port`, `tls` | да | да | — | да |
| `quic` | 1.12 | `server`, `server_port`, `tls` | да | только стандартный TLS | — | да (`with_quic`) |
| `https` | 1.12 | `server`, `server_port`, `path`, `headers`, `method`, `tls` | да | да | — | да |
| `h3` | 1.12 | как у `https` | да | только стандартный TLS | — | да (`with_quic`) |
| `dhcp` | 1.12 | `interface` | да | — | — | да (`with_dhcp`) |
| `mdns` | 1.14 | `interface` | принимаются, не используются | — | да | да |
| `fakeip` | 1.12 | `inet4_range`, `inet6_range` | — | — | — | да |
| `tailscale` | 1.12 | `endpoint`, `accept_default_resolvers`, `accept_search_domain` | — | — | да | да (`with_tailscale`) |
| `resolved` | 1.12 | `service`, `accept_default_resolvers` | — | — | да | нет: `check` падает |
| `openconnect` | 1.14 | `endpoint`, `accept_default_resolvers`, `accept_search_domain` | — | — | да | да (`with_openconnect`) |
| `openvpn` | 1.14 | `endpoint`, `accept_default_resolvers`, `accept_search_domain` | — | — | да (по коду) | да (`with_openvpn`) |

Общие ограничения: сервер `fakeip` может быть только один (`multiple fakeip server are not supported`) и не может быть сервером по умолчанию. В сборке без соответствующего тега (`with_quic`, `with_dhcp`, …) тип распознаётся, но создание сервера завершается ошибкой.

Исходники: option/dns.go (DNSServerOptions), constant/dns.go, include/registry.go (DNSTransportRegistry), include/*_stub.go, dns/transport_manager.go (Create), dns/transport_registry.go.

### Dial Fields у DNS-серверов

Типы `local`, `udp`, `tcp`, `tls`, `quic`, `https`, `h3`, `dhcp` (и формально `mdns`) включают Dial Fields — те же, что у исходящих; полное описание в [shared.md](shared.md). Ниже — их список и то, что специфично для DNS.

| Поле | Тип | По умолчанию | Смысл и ограничения для DNS |
|---|---|---|---|
| `detour` | string -> outbound | — | Исходящий, через который сервер подключается к апстриму. Без него сервер ходит напрямую (как пустой direct), а не через исходящий по умолчанию. |
| `domain_resolver` | string\|object -> dns server | — | Сервер для разрешения доменного `server`; объект — `server`, `timeout`, `strategy`, `disable_cache`, `disable_optimistic_cache`, `rewrite_ttl`, `client_subnet` ([shared.md](shared.md)). Запрос идёт прямо в этот сервер, мимо правил. Является зависимостью запуска (см. ниже). |
| `domain_strategy` | string | `""` | Устарело в 1.12 (плановое удаление 1.14). Учитывается только при доменном `server`; в 1.14.2 его использование фатально без `ENABLE_DEPRECATED_LEGACY_DOMAIN_STRATEGY_OPTIONS=true`. Замена — `domain_resolver.strategy`. |
| `bind_interface` | string | — | Привязать сокеты к интерфейсу. |
| `inet4_bind_address` | string | — | Локальный IPv4-адрес. |
| `inet6_bind_address` | string | — | Локальный IPv6-адрес. |
| `bind_address_no_port` | bool | `false` | Не резервировать порт при привязке. Только Linux: на Windows `true` — ошибка `check` (`bind_address_no_port is only supported on Linux`). |
| `routing_mark` | int\|string | `0` | fwmark, число или строка вида `"0x1234"`. Только Linux: на Windows ненулевое значение — ошибка `check`. |
| `reuse_addr` | bool | `false` | SO_REUSEADDR. |
| `netns` | string -> network_namespace | — | Сетевое пространство имён (только Linux; на Windows check проходит, ошибка — при подключении). |
| `protect_path` | string | — | Сокет защиты от VPN-петли (Android). |
| `connect_timeout` | duration | `5s` | Тайм-аут установления соединения. |
| `tcp_fast_open` | bool | `false` | TCP Fast Open. |
| `tcp_multi_path` | bool | `false` | MPTCP. |
| `disable_tcp_keep_alive` | bool | `false` | Отключить keep-alive. |
| `tcp_keep_alive` | duration | `5m` | Начальный период keep-alive. |
| `tcp_keep_alive_interval` | duration | `75s` | Интервал keep-alive. |
| `udp_fragment` | bool | `false` | Разрешить фрагментацию UDP (у DNS-серверов умолчание не меняется, в отличие от исходящего `direct`). |
| `network_strategy` | string | — | Выбор сети; действует только в графических клиентах с `route.auto_detect_interface`. Вместе с `bind_interface`, `inet4_bind_address`, `inet6_bind_address` или `tcp_fast_open` — ошибка `check`. |
| `network_type` | string\|[string] | — | Типы сетей для `network_strategy`. |
| `fallback_network_type` | string\|[string] | — | Резервные типы сетей. |
| `fallback_delay` | duration | `300ms` | Задержка перед резервной попыткой. |

Что важно именно для DNS-серверов:

- `server` — доменное имя: нужен `domain_resolver`, если нет `detour` (иначе `check`: `missing domain resolver for domain server address`). С `detour`, но без `domain_resolver`, имя передаётся исходящему как есть и резолвится на той стороне. Строка вида `1.1.1.1:53` или URL в `server` считается доменным именем — порт указывается в `server_port`.
- `domain_resolver` задаёт порядок запуска серверов. Ссылка на несуществующий сервер или цикл `check` не замечает; запуск падает с `dependency[X] not found for server[Y]` или `circular server dependency: a -> b -> a`. Зависимость появляется, даже если `server` — IP.
- `detour` на несуществующий исходящий: `check` проходит; `udp`, `tcp`, `tls`, `quic`, `https`, `h3` падают при запуске (`outbound detour not found: X`). `local` и `dhcp` проверяют `detour` лениво — по коду ошибка возникает на каждом запросе, а запуск проходит.
- `detour` на «пустой» direct-исходящий (без единого поля Dial Fields): `check` проходит, запуск падает (`detour to an empty direct outbound makes no sense`) для тех же шести типов; у `local` и `dhcp` — ошибка на запросе. Такой `detour` бессмыслен: без него сервер и так ходит напрямую.
- При TUN с `auto_route` прямые DNS-соединения должны идти мимо туннеля: включайте `route.auto_detect_interface` или задавайте `bind_interface` ([route.md](route.md)).

Исходники: option/outbound.go (DialerOptions, AbstractDialerOptions, DomainResolveOptions), option/dns.go (RawLocalDNSServerOptions, RemoteDNSServerOptions), dns/transport_dialer.go, dns/transport_adapter.go, dns/transport_manager.go (startTransports), common/dialer/dialer.go, common/dialer/detour.go.

### Сервер `local`

Системный резолвер: берёт DNS-серверы и search-домены из настроек ОС. Отвечает на запросы любого типа.

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `prefer_go` | bool | `false` | С 1.13. Резолвить своими силами: на Linux не ходить через D-Bus systemd-resolved, на Apple — не использовать `getaddrinfo` в Network Extension. На Windows ни на что не влияет. В графическом клиенте Android `local` всегда идёт через платформу. |
| `neighbor_domain` | string\|[string] | — | С 1.14. Суффиксы, для которых A/AAAA берутся из таблицы соседей (neighbor resolver). Каждый элемент обязан начинаться с `.` (иначе ошибка `check`); часть имени перед суффиксом не должна содержать точек; `"."` — любое одноуровневое имя (`nas`). Neighbor resolver есть только на Linux и macOS — на Windows поле ничего не делает. |
| Dial Fields | | | См. [выше](#dial-fields-у-dns-серверов). Используются для запросов к системным DNS-серверам. |

Порядок ответа (1.14): сначала A/AAAA из системного файла hosts, затем имена соседей (`neighbor_domain`), затем имена в `*.local.` и link-local обратных зонах — через встроенный mDNS (на Apple — через систему); остальное — к апстриму.

На Windows (по коду): список серверов берётся из `GetAdaptersAddresses` — только адаптеры в состоянии Up с назначенным шлюзом, не туннельного типа и не принадлежащие самому sing-box (TUN); запросы идут по UDP на порт 53 собственным диалером (то есть с учётом `detour` и `bind_interface`), 2 попытки по 5 с на каждый сервер; если ничего не найдено — `127.0.0.1:53` и `[::1]:53`. Файл hosts — `<системный каталог>\drivers\etc\hosts`. `preferred_by` на `local` совпадает с именами из hosts, именами соседей и зонами mDNS.

Отличие от legacy `"address": "local"`: старый сервер обрабатывал только запросы адресов и по умолчанию ходил через исходящий по умолчанию; новый — все типы и напрямую.

Исходники: option/dns.go (LocalDNSServerOptions), dns/transport/local/local.go, local_preferred.go, local_neighbor.go, local_shared.go, local_other.go, local_resolved_linux.go, local_darwin.go, dns/transport/local/systemconfig/source_windows.go, systemconfig/config.go, route/neighbor_resolver_stub.go.

### Сервер `hosts`

Отвечает из файлов hosts и встроенной таблицы.

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `path` | string\|[string] | системный hosts | Файлы hosts. По умолчанию `/etc/hosts`, на Windows `<системный каталог>\drivers\etc\hosts` (через `GetSystemDirectory`). Переменные раскрываются в стиле `$VAR`/`${VAR}` (не `%VAR%`); относительный путь — от рабочего каталога (`-D`). Отсутствующий файл — не ошибка: он просто пуст. Файл перечитывается при изменении (проверка не чаще раза в 5 с). |
| `predefined` | object | — | Таблица `{"имя": "IP" \| ["IP", …]}`; приоритет над файлами. Невалидный IP — ошибка разбора. |

Отвечает только на A/AAAA (TTL 600); на прочие типы и неизвестные имена — NXDOMAIN. Поэтому `hosts` ставят не в `final`, а правилом: с 1.14 — `{"preferred_by": "<тег hosts>", "server": "<тег hosts>"}`, до 1.14 — через `ip_accept_any` (теперь это legacy-режим).

Исходники: option/dns.go (HostsDNSServerOptions), dns/transport/hosts/hosts.go, hosts_file.go, hosts_windows.go, hosts_unix.go.

### Серверы `udp` и `tcp`

Классический DNS по UDP или TCP.

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `server` | string | — (обязательно) | IP или доменное имя без порта и схемы (IPv6 можно в скобках). Без него — `invalid server address: :53` на `check`. Домен требует `domain_resolver` или `detour`. |
| `server_port` | int | `53` | Порт. |
| Dial Fields | | | См. [выше](#dial-fields-у-dns-серверов). |

`udp` при усечённом ответе повторяет запрос по TCP к тому же серверу; `tcp` переиспользует соединения.

Исходники: option/dns.go (RemoteDNSServerOptions, DNSServerAddressOptions), dns/transport/udp.go, dns/transport/tcp.go, dns/transport/multiplexer.go.

### Сервер `tls` (DoT)

DNS поверх TLS.

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `server` | string | — (обязательно) | Как у `udp`. |
| `server_port` | int | `853` | Порт. |
| `tls` | object | — | Исходящий TLS ([shared.md](shared.md)). TLS включён всегда, `enabled` игнорируется. SNI по умолчанию — значение `server` (для IP сертификат должен содержать этот IP). |
| Dial Fields | | | См. [выше](#dial-fields-у-dns-серверов). |

Исходники: option/dns.go (RemoteTLSDNSServerOptions), dns/transport/tls.go.

### Сервер `quic` (DoQ)

DNS поверх QUIC (RFC 9250).

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `server` | string | — (обязательно) | Как у `udp`. |
| `server_port` | int | `853` | Порт. |
| `tls` | object | — | Исходящий TLS; ALPN по умолчанию `doq`. QUIC рассчитан на стандартный TLS-стек: `check` с `utls` проходит (проверено), но соединение с uTLS/Reality, судя по устройству кода, не установится (при работе не проверялось; у `h3` та же конфигурация отвергается уже на `check`). |
| Dial Fields | | | См. [выше](#dial-fields-у-dns-серверов). |

Исходники: dns/transport/quic/quic.go, include/quic.go, include/quic_stub.go.

### Серверы `https` (DoH) и `h3` (DoH3)

DNS поверх HTTPS (HTTP/2 или HTTP/1.1) и поверх HTTP/3.

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `server` | string | — (обязательно) | IP или домен, не URL (`https://…` в `server` считается доменом и требует `domain_resolver`). |
| `server_port` | int | `443` | Порт; в URL попадает, только если не 443. |
| `path` | string | `"/dns-query"` | Путь запроса. |
| `headers` | object | — | Дополнительные заголовки `{"Имя": "значение" \| ["…"]}`. Заголовок `Host` не отправляется как есть: он становится хостом в URL; без него хост — `tls.server_name`, иначе `server`. |
| `method` | string | — | Есть в коде, в документации нет; не используется — запрос всегда POST. |
| `tls` | object | — | Исходящий TLS. Для `https` ALPN по умолчанию `h2`, `http/1.1`. Для `h3` нужен стандартный TLS: `utls`/`reality` — ошибка `check` (`unsupported usage for uTLS`). |
| Dial Fields | | | См. [выше](#dial-fields-у-dns-серверов). |

Исходники: option/dns.go (RemoteHTTPSDNSServerOptions), dns/transport/https.go, dns/transport/https_transport.go, dns/transport/quic/http3.go.

### Сервер `dhcp`

Берёт DNS-серверы из DHCP указанного интерфейса и опрашивает их.

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `interface` | string | интерфейс по умолчанию | Интерфейс для DHCP-запроса. Без него нужен монитор интерфейсов; если его нет — при запуске `missing monitor for auto DHCP, set route.auto_detect_interface` (на Windows монитор обычно создаётся всегда). |
| `prefer_go`, `neighbor_domain` | | | Принимаются (структура наследует поля `local`), но кодом `dhcp` не используются; в документации их нет. |
| Dial Fields | | | Используются для запросов к полученным серверам; `detour` проверяется лениво (на запросе). |

`preferred_by` с `dhcp` не работает: запуск падает с `DNS server type does not support preferred_by: dhcp` (хотя changelog 1.14 заявляет поддержку).

Исходники: option/dns.go (DHCPDNSServerOptions), dns/transport/dhcp/dhcp.go, dhcp_shared.go, include/dhcp.go.

### Сервер `mdns`

С 1.14. Multicast DNS в локальной сети (224.0.0.251 / ff02::fb, порт 5353, ожидание ответов 1 с или до дедлайна запроса).

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `interface` | string\|[string] | все подходящие | Интерфейсы для запросов; по умолчанию все поднятые, с multicast, не loopback. |
| Dial Fields, `prefer_go`, `neighbor_domain` | | | Принимаются, но не используются: собственного диалера у `mdns` нет, `domain_resolver` лишь добавляет зависимость запуска. |

`preferred_by` совпадает с `*.local.` и link-local обратными зонами (`254.169.in-addr.arpa.`, `8/9/a/b.e.f.ip6.arpa.`). Сервер `local` уже отправляет эти зоны в mDNS, так что отдельный `mdns` нужен только для `preferred_by` или самостоятельного использования.

Исходники: option/dns.go (MDNSDNSServerOptions), dns/transport/mdns/mdns.go.

### Сервер `fakeip`

Выдаёт фиктивные адреса из заданных диапазонов, см. [FakeIP](#fakeip).

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `inet4_range` | string (префикс) | — | Диапазон IPv4, например `198.18.0.0/15`. |
| `inet6_range` | string (префикс) | — | Диапазон IPv6, например `fc00::/18`. |

Значений по умолчанию нет (в документации это примеры); нужен хотя бы один диапазон, иначе `check`: `at least one of inet4_range or inet6_range must be set`.

Исходники: option/dns.go (FakeIPDNSServerOptions), dns/transport/fakeip/fakeip.go, store.go, memory.go.

### Сервер `tailscale`

MagicDNS эндпоинта Tailscale.

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `endpoint` | string -> endpoint | — (обязательно) | Тег эндпоинта `tailscale`. Пусто — ошибка `check` (`missing tailscale endpoint tag`); несуществующий или не Tailscale — ошибка запуска (`endpoint not found` / `endpoint is not Tailscale`). На один эндпоинт — один такой сервер. |
| `accept_default_resolvers` | bool | `false` | Отправлять имена вне MagicDNS в резолверы, выданные tailnet; без этого — NXDOMAIN. |
| `accept_search_domain` | bool | `false` | С 1.14. Одноуровневые имена (`my-device`) пробуются с каждым search-доменом tailnet; резолверы по умолчанию для них не используются. |

Исходники: option/tailscale.go (TailscaleDNSServerOptions), protocol/tailscale/dns_transport.go, include/tailscale.go.

### Сервер `resolved`

Только Linux: DNS-настройки, переданные службе `resolved` (эмуляция systemd-resolved).

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `service` | string -> service | — (обязательно) | Тег службы `resolved`; проверяется при запуске. |
| `accept_default_resolvers` | bool | `false` | Использовать резолверы по умолчанию (`SetLinkDefaultRoute` или домен `~.`) для остальных имён; без этого — NXDOMAIN. |

На Windows `check` падает: `resolved DNS server is only supported on Linux`. Поля `ndots`, `timeout`, `attempts`, `rotate` в коде закомментированы и не принимаются.

Исходники: option/resolved.go (ResolvedDNSServerOptions), service/resolved/transport.go, service/resolved/stub.go.

### Серверы `openconnect` и `openvpn`

С 1.14. DNS, выданный VPN-сервером через эндпоинт OpenConnect или клиентский эндпоинт OpenVPN. Настройки в систему не устанавливаются.

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `endpoint` | string -> endpoint | — (обязательно) | Тег эндпоинта `openconnect` или клиента OpenVPN. Пусто — ошибка `check` (`missing endpoint tag`); несуществующий или чужого типа — ошибка запуска. У `openconnect` на эндпоинт — один сервер. |
| `accept_default_resolvers` | bool | `false` | Отправлять имена, не подпадающие под выданные split-DNS-суффиксы и search-домены, в общие выданные резолверы; иначе NXDOMAIN. |
| `accept_search_domain` | bool | `false` | Одноуровневые имена пробуются с каждым выданным search-доменом. |

OpenVPN: учитывается современная опция `dns server` (plain, DoT, DoH, свои порты, SNI, `resolve-domains`; активна группа с наименьшим приоритетом) и, при её отсутствии, `dhcp-option DNS/DNS6/DOMAIN-ROUTE`; требование DNSSEC (`dnssec yes`) отвергается. `preferred_by` работает с обоими типами (для `openvpn` — по коду; в таблице документации его нет).

Исходники: option/openconnect.go (OpenConnectDNSServerOptions), option/openvpn.go (OpenVPNDNSServerOptions), protocol/openconnect/dns_transport.go, protocol/openvpn/dns_transport.go, include/openconnect.go, include/openvpn.go.

## Устаревший формат серверов и миграция

Старый формат (сервер без `type`, адрес в `address`) устарел в 1.12 и удалён в 1.14. В 1.14.2 сервер без `type` или с `"type": "legacy"` — ошибка разбора (`legacy DNS server formats are deprecated in sing-box 1.12.0 and removed in sing-box 1.14.0`); переменной окружения, возвращающей его, нет. Блок `dns.fakeip` — такая же ошибка.

Поля старого сервера и их замена:

| Старое поле | Тип | Замена в 1.14 |
|---|---|---|
| `tag` | string | `tag` (без изменений). |
| `address` | string | `type` + `server`/`server_port`/`path` (таблица ниже). |
| `address_resolver` | string -> dns server | `domain_resolver` в Dial Fields. |
| `address_strategy` | string | `domain_resolver.strategy` (объектная форма). |
| `strategy` | string | `dns.strategy`, `domain_resolver.strategy` или правила по `query_type` (стратегия в действии правила в 1.14 устарела). |
| `detour` | string -> outbound | `detour`. Внимание: раньше без `detour` сервер ходил через исходящий по умолчанию (часто прокси), теперь — напрямую. Чтобы сохранить прежнее поведение, укажите `detour` явно. |
| `client_subnet` | string | `client_subnet` в действии правила, `domain_resolver.client_subnet` или `dns.client_subnet`. |

| Старый `address` | Новый сервер |
|---|---|
| `local` | `{"type": "local"}` |
| `8.8.8.8`, `udp://8.8.8.8` | `{"type": "udp", "server": "8.8.8.8"}` |
| `tcp://1.0.0.1` | `{"type": "tcp", "server": "1.0.0.1"}` |
| `tls://dns.google` | `{"type": "tls", "server": "dns.google", "domain_resolver": "…"}` |
| `https://1.1.1.1/dns-query` | `{"type": "https", "server": "1.1.1.1"}` (+ `path`, если не `/dns-query`) |
| `quic://dns.adguard.com` | `{"type": "quic", "server": "dns.adguard.com", "domain_resolver": "…"}` |
| `h3://8.8.8.8/dns-query` | `{"type": "h3", "server": "8.8.8.8"}` |
| `dhcp://auto` / `dhcp://en0` | `{"type": "dhcp"}` / `{"type": "dhcp", "interface": "en0"}` |
| `fakeip` + `dns.fakeip` | `{"type": "fakeip", "inet4_range": "…", "inet6_range": "…"}` |
| `rcode://refused` | сервера нет; правило с условием и действием, например `{"domain": "example.com", "action": "predefined", "rcode": "REFUSED"}` |

Старые имена rcode (`success`, `format_error`, `server_failure`, `name_error`, `not_implemented`, `refused`) в `predefined` не принимаются (`unknown rcode: refused`) — нужны `NOERROR`, `FORMERR`, `SERVFAIL`, `NXDOMAIN`, `NOTIMP`, `REFUSED`.

Родственные миграции 1.12: DNS-правило по `outbound` заменяется на `domain_resolver` у исходящих или `route.default_domain_resolver` ([route.md](route.md)); `domain_strategy` в Dial Fields — на `domain_resolver.strategy`.

Исходники: option/dns.go (legacyDNSServerRemovedMessage, legacyDNSFakeIPRemovedMessage, DNSOptions.UnmarshalJSONContext), constant/dns.go (DNSTypeLegacy), docs/migration.md.

## FakeIP

FakeIP отвечает на A/AAAA адресом из служебного диапазона и запоминает пару «адрес -> домен»; маршрутизация потом восстанавливает домен по такому адресу ([route.md](route.md)). На Windows это имеет смысл только вместе с TUN, чей маршрут покрывает диапазоны FakeIP ([inbounds.md](inbounds.md)).

- Один сервер `fakeip` на конфиг; не может быть `final` (или первым сервером при пустом `final`); не может быть сервером действия `evaluate` (`evaluate action cannot use fakeip server`).
- Отвечает только на A/AAAA; запрос другого типа, попавший в `fakeip`, завершается ошибкой `only IP queries are supported by fakeip`. Поэтому правило на `fakeip` ограничивают `query_type: ["A", "AAAA"]`. Если диапазон для семейства не задан, ответ — пустой NOERROR.
- TTL ответа 600 с; ответы не кэшируются и не попадают в `reverse_mapping`.
- Работает только для клиентских запросов (`hijack-dns`). При внутреннем разрешении правило, ведущее в `fakeip`, пропускается, и перебор идёт дальше.
- Выдача адресов начинается с адреса сети + 1. Состояние хранится в памяти или, при `experimental.cache_file.store_fakeip`, в файле кэша; при смене диапазонов сбрасывается.
- Старый блок `dns.fakeip` (`enabled`, `inet4_range`, `inet6_range`) удалён в 1.14 — ошибка разбора.

Исходники: dns/transport/fakeip/fakeip.go, store.go, memory.go, dns/transport_manager.go (Create), dns/router.go (resolveDNSRoute, validateEvaluateFakeIPRules, recordReverseMapping).

## DNS-правила

Каждый элемент `dns.rules` — обычное правило (`"type": "default"` или без `type`) или логическое (`"type": "logical"`). Правило = условия + действие ([действия](#действия-dns-правил)); поля действия пишутся в том же объекте. `action` необязателен: по умолчанию `route` (документация помечает его обязательным — это не так).

### Логика сопоставления

- Внутри одного поля-списка значения объединяются через ИЛИ.
- Поля объединяются в группы через И: (`domain` || `domain_suffix` || `domain_keyword` || `domain_regex` || `ip_cidr` || `ip_is_private` || `ip_accept_any`) && (`port` || `port_range`) && (`source_ip_cidr` || `source_ip_is_private`) && (`source_port` || `source_port_range`) && все остальные поля.
- Rule-set, состоящий ровно из одного обычного правила без `invert`, вливается в эти группы внешнего правила; любой другой rule-set проверяется как отдельное «прочее» поле (изменено в 1.14). Разные rule-set в одном `rule_set` — через ИЛИ. Подробно — [route.md](route.md#семантика-rule_set-в-правиле).
- `invert` инвертирует итог. Правило без единого условия, но с действием (`{"server": "x"}`) совпадает со всеми запросами (`invert` на нём ничего не меняет).
- Пустые элементы в `domain`, `domain_suffix` запрещены (`empty item is not allowed`).
- `domain_suffix` без ведущей точки совпадает с самим доменом и его поддоменами; с точкой — только с поддоменами (поведение с 1.9).

Исходники: route/rule/rule_abstract.go, route/rule/rule_item_domain.go, route/rule/rule_item_rule_set.go.

### Поля условий обычного правила

Поля запроса:

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `inbound` | string\|[string] -> inbound | — | Входящий, из которого пришёл запрос. |
| `ip_version` | int | — | `4` (запрос A) или `6` (AAAA); другое — ошибка `check` (`invalid ip version`). Изменено в 1.14: действует и на внутренние разрешения; включает новый режим правил. |
| `query_type` | string\|int\|[string\|int] | — | Тип запроса: имя (`A`, `AAAA`, `HTTPS`, `CNAME`, …) или число. Изменено в 1.14 как `ip_version`; включает новый режим. |
| `query_client_subnet` | string\|[string] | — | С 1.14. ECS в запросе: префикс совпадает, если он не уже присланной подсети и содержит её адрес; IP без маски -> `/32`/`/128`. |
| `query_dnssec` | bool | `false` | С 1.14. Запрос с битом DO (DNSSEC OK). |
| `network` | string\|[string] | — | `tcp` или `udp` — транспорт входящего запроса. |
| `auth_user` | string\|[string] | — | Имя пользователя входящего с аутентификацией. |
| `protocol` | string\|[string] | — | Протокол, определённый сниффингом (`tls`, `http`, `quic`, `dns`, `stun`, `bittorrent`, `dtls`, `ssh`, `rdp`, `ntp`). |
| `clash_mode` | string | — | Текущий режим Clash API ([experimental.md](experimental.md)). |

Поля домена:

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `domain` | string\|[string] | — | Точное совпадение имени. |
| `domain_suffix` | string\|[string] | — | Суффикс (см. логику выше). |
| `domain_keyword` | string\|[string] | — | Подстрока. |
| `domain_regex` | string\|[string] | — | Регулярное выражение (синтаксис Go); ошибка компиляции — ошибка `check`. |
| `preferred_by` | string\|[string] -> dns server | — | С 1.14. Имя, которое перечисленные серверы считают «своим»: `hosts` — записи таблицы и файлов; `local` — hosts, соседи, зоны mDNS; `mdns` — `*.local.` и link-local обратные зоны; `tailscale` — хосты MagicDNS и маршрутные суффиксы; `openconnect`, `openvpn` — выданные split-DNS и search-домены; `resolved` — домены ссылок systemd-resolved. Несуществующий тег или сервер другого типа (`udp`, `dhcp`, `fakeip`, …) `check` пропускает, а запуск падает (`DNS server not found: X` / `DNS server type does not support preferred_by: T`). |

Поля источника и портов:

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `source_ip_cidr` | string\|[string] | — | IP/подсеть источника запроса. |
| `source_ip_is_private` | bool | `false` | Источник — непубличный адрес. |
| `source_port` | int\|[int] | — | Порт источника. |
| `source_port_range` | string\|[string] | — | Диапазоны `"1000:2000"`, `":3000"`, `"4000:"`. |
| `port` | int\|[int] | — | Порт назначения запроса. |
| `port_range` | string\|[string] | — | Диапазоны портов назначения. |
| `source_mac_address` | string\|[string] | — | С 1.14. MAC устройства-источника (neighbor resolver: Linux, macOS, графические клиенты Android/macOS). На Windows не срабатывает. |
| `source_hostname` | string\|[string] | — | С 1.14. Имя устройства из аренд DHCP; платформы как у `source_mac_address`. На Windows не срабатывает. |

Поля процесса и платформы:

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `process_name` | string\|[string] | — | Имя процесса (Linux, Windows, macOS). |
| `process_path` | string\|[string] | — | Полный путь процесса; на Windows — Win32-путь `C:\…` (с 1.9). |
| `process_path_regex` | string\|[string] | — | С 1.10. Путь процесса по регулярному выражению. |
| `package_name` | string\|[string] | — | Имя пакета Android. |
| `package_name_regex` | string\|[string] | — | С 1.14. Имя пакета Android по регулярному выражению. |
| `user` | string\|[string] | — | Имя пользователя (только Linux). |
| `user_id` | int\|[int] | — | UID (только Linux). |
| `network_type` | string\|[string] | — | С 1.11. `wifi`, `cellular`, `ethernet`, `other` (графические клиенты Android/Apple). |
| `network_is_expensive` | bool | `false` | С 1.11. Лимитная сеть (графические клиенты Android/Apple). |
| `network_is_constrained` | bool | `false` | С 1.11. Режим экономии трафика (графические клиенты Apple). |
| `wifi_ssid` | string\|[string] | — | SSID (графические клиенты Android/Apple; Linux и Windows — с 1.13, на Windows через WLAN API). Монитор Wi-Fi включается, если поле есть в правилах маршрутизации или DNS. |
| `wifi_bssid` | string\|[string] | — | BSSID (там же). |
| `interface_address` | object | — | С 1.13. `{"имя интерфейса": префикс \| [префиксы]}` (Linux, Windows, macOS). |
| `network_interface_address` | object | — | С 1.13. `{"тип сети": префикс \| [префиксы]}`, типы как у `network_type` (графические клиенты Android/Apple). |
| `default_interface_address` | string\|[string] | — | С 1.13. Адрес интерфейса по умолчанию (Linux, Windows, macOS). |

Поля ответа и rule-set:

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `rule_set` | string\|[string] -> rule-set | — | Rule-set из `route.rule_set`. Несуществующий тег — ошибка `check` (`rule-set not found`). Rule-set с полями `ip_cidr` влияет на режим правил (см. [режимы](#режимы-dns-правил-legacy-и-новый)). |
| `rule_set_ip_cidr_match_source` | bool | `false` | С 1.10. `ip_cidr` внутри rule-set сопоставлять с IP источника. |
| `match_response` | bool\|string | — | С 1.14. Сопоставлять с ответом, полученным ранее действием `evaluate`: `true` — последний ответ `evaluate` без `tag`, строка — ответ `evaluate` с этим тегом. Пустая строка — ошибка разбора. Если ответа нет (сервер не найден, запрос не удался), правило не совпадает (при `invert` — совпадает). |
| `ip_cidr` | string\|[string] | — | Адреса в ответе. С `match_response` — поле ответа; без него — legacy-фильтр адресов (устарел в 1.14, удаление в 1.16). |
| `ip_is_private` | bool | `false` | Непубличный адрес в ответе; то же разделение. |
| `ip_accept_any` | bool | `false` | С 1.12. В ответе есть хотя бы один адрес; то же разделение. |
| `response_rcode` | string\|int | — | С 1.14. Код ответа (значения как у `predefined.rcode`). Требует `match_response`. |
| `response_answer` | string\|[string] | — | С 1.14. Записи в секции Answer ([формат записей](#формат-dns-записей-и-кодов-ответа)); совпадение по содержимому записи. Требует `match_response`. |
| `response_ns` | string\|[string] | — | С 1.14. Записи в секции Authority. Требует `match_response`. |
| `response_extra` | string\|[string] | — | С 1.14. Записи в секции Additional. Требует `match_response`. |
| `invert` | bool | `false` | Инвертировать итог правила. |

Устаревшие и удалённые поля:

| Поле | Тип | Статус |
|---|---|---|
| `outbound` | string\|[string] -> outbound | Устарело в 1.12 (плановое удаление 1.14). В 1.14.2 ещё разбирается, но его наличие фатально (`check` падает) без `ENABLE_DEPRECATED_OUTBOUND_DNS_RULE_ITEM=true`; с переменной — предупреждение и прежняя работа (`any` — любой исходящий). Замена — `domain_resolver`/`route.default_domain_resolver`. |
| `rule_set_ip_cidr_accept_empty` | bool | С 1.10, устарело в 1.14, удаление в 1.16. Разрешено только в legacy-режиме (с предупреждением); в новом режиме — ошибка `check`. |
| `rule_set_ipcidr_match_source` | bool | Переименовано в 1.10, удалено в 1.11. Ошибка `check` (`rule_set_ipcidr_match_source is deprecated in sing-box 1.10.0 and removed in sing-box 1.11.0`) только вместе с непустым `rule_set`; без `rule_set` поле молча игнорируется (проверено). |
| `geosite`, `geoip`, `source_geoip` | string\|[string] | Удалены в 1.12: ошибка `check` (`geosite/geoip database is deprecated in sing-box 1.8.0 and removed in sing-box 1.12.0`). Замена — rule-set. |
| `server`, `disable_cache`, `rewrite_ttl`, `client_subnet` на уровне правила | | С 1.11 это параметры действия `route` — пишутся там же, в объекте правила, так что старые конфиги продолжают работать. |

На Windows все поля принимаются `check`, но платформенно недоступные (`user`, `user_id`, `package_name*`, `network_is_*`, `network_interface_address`, `source_mac_address`, `source_hostname`) просто никогда не совпадают. Исключение — `network_type`: тип сети на Windows не определяется и остаётся нулевым значением (`wifi`), поэтому по коду `network_type: wifi` совпадает при любом интерфейсе по умолчанию, а остальные значения — никогда (тот же `NetworkTypeItem`, что в правилах маршрутизации, см. [route.md](route.md); запуском не проверялось). `wifi_ssid`/`wifi_bssid` на Windows работают (с 1.13).

Исходники: option/rule_dns.go (RawDefaultDNSRule), route/rule/rule_dns.go (NewDefaultDNSRule), route/rule/rule_item_*.go (в частности rule_item_preferred_by_dns.go, rule_item_query_client_subnet.go, rule_item_query_dnssec.go, rule_item_response_rcode.go, rule_item_response_record.go, rule_item_outbound.go), route/neighbor_resolver_stub.go.

### Логические правила

Объединяют вложенные правила через И/ИЛИ.

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `type` | string | — | `logical`. |
| `mode` | string | — (обязательно) | `and` или `or`; иное — ошибка `check`. |
| `rules` | [object] | — (обязательно) | Вложенные правила (обычные или логические). Пустой список или вложенное правило без условий — `missing conditions`. |
| `invert` | bool | `false` | Инвертировать итог. |
| поля действия | | | Действие логического правила — в том же объекте. |

Во вложенных правилах поля действия запрещены: ключи `action`, `race`, `server`, `tag`, `speculative`, `strategy`, `timeout`, `disable_cache`, `disable_optimistic_cache`, `rewrite_ttl`, `client_subnet`, `remove_client_subnet` дают ошибку разбора `DNS rule action is not supported in nested rules`. `evaluate` допустим только в правилах верхнего уровня. `respond` на логическом правиле не может ссылаться на ответ по тегу из вложенных правил (`respond on a logical rule cannot bind a match_response tag from its sub rules`). `race` на логическом правиле требует `match_response` хотя бы в одном вложенном правиле.

Исходники: option/rule_dns.go (RawLogicalDNSRule), option/rule_nested.go, route/rule/rule_nested_action.go, route/rule/rule_dns.go (NewLogicalDNSRule).

### Формат DNS-записей и кодов ответа

Используется в `predefined.answer/ns/extra` и `response_answer/ns/extra`.

- Запись — строка в формате зонного файла: `"a.lan. IN A 10.0.0.1"`, `"a.lan. 60 IN AAAA ::1"`, `"a.lan. IN TXT \"text\""`. Имя владельца должно быть полным, с точкой в конце (`a.lan IN A …` — ошибка разбора). TTL по умолчанию 3600, класс по умолчанию IN. Допускается также base64 от записи в wire-формате.
- В `predefined` владелец вида `*.a.lan.` заменяется на имя из вопроса, если оно оканчивается на `.a.lan.` (в документации не описано).
- В `response_*` запись совпадает, если в ответе есть запись с тем же содержимым (сравнение без учёта TTL).
- Код ответа — число или имя по таблице miekg/dns: `NOERROR` (по умолчанию в `predefined`), `FORMERR`, `SERVFAIL`, `NXDOMAIN`, `NOTIMP`, `REFUSED`, а также более редкие (`YXDOMAIN`, `NOTAUTH`, …).

Исходники: option/dns_record.go (DNSRCode, DNSRecordOptions), route/rule/rule_action.go (RuleActionPredefined.Response, rewriteRecords), route/rule/rule_item_response_record.go.

## Действия DNS-правил

С 1.11 правило содержит действие. Общие поля:

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `action` | string | `route` | `route`, `evaluate`, `respond`, `route-options`, `reject`, `predefined`; иное — ошибка разбора. |
| `race` | bool | `false` | С 1.14. См. [race и speculative](#race-и-speculative). Допустим только с `route`, `respond`, `reject`, `predefined`; требует `match_response` (у логического правила — во вложенных); несовместим с `speculative`. |

Параметры маршрутизации запроса (общие для `route`, `evaluate`, `route-options`):

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `strategy` | string | `""` | С 1.12, устарело в 1.14 (удаление в 1.16). Стратегия для этого запроса. Любое непустое значение включает legacy-режим; вместе с признаками нового режима — ошибка `check`. |
| `disable_cache` | bool | `false` | Не брать ответ из кэша и не сохранять его. |
| `disable_optimistic_cache` | bool | `false` | С 1.14. Не отдавать устаревший ответ оптимистичного кэша. Включает новый режим. |
| `rewrite_ttl` | int | — | Переписать TTL записей ответа. |
| `timeout` | duration | `dns.timeout` | С 1.14. Тайм-аут этого запроса. |
| `client_subnet` | string | — | ECS для запроса (IP -> `/32`/`/128`); перекрывает `dns.client_subnet`. |
| `remove_client_subnet` | bool | `false` | С 1.14. Убрать ECS из запроса и не добавлять `dns.client_subnet`. Вместе с `client_subnet` — ошибка `check`. |

Исходники: option/rule_action.go (_DNSRuleAction, DNSRouteActionOptions, DNSEvaluateActionOptions, AbstractDNSRouteActionOptions, DNSRouteOptionsActionOptions, RejectActionOptions, DNSRouteActionPredefined), route/rule/rule_action.go (NewDNSRuleAction), route/rule/rule_dns.go (validateDNSRuleAction), dns/router.go.

### `route`

Отправить запрос на сервер и завершить перебор (действие по умолчанию).

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `server` | string -> dns server | — (обязательно) | Целевой сервер. Пусто — ошибка `check` (`missing server field`). Несуществующий тег не проверяется ни `check`, ни запуском: на каждом подходящем запросе в лог пишется `transport not found: X`, правило пропускается. Правило на `fakeip` пропускается при внутреннем разрешении. |
| `speculative` | bool | `false` | С 1.14. Отправить запрос сразу, не дожидаясь решения предшествующих `race`-правил. Без предшествующего `race`-правила бесполезно (предупреждение в логе). Включает новый режим. |
| параметры маршрутизации | | | См. таблицу выше. |

### `evaluate`

С 1.14. Отправить запрос и сохранить ответ для последующих правил, не завершая перебор. Только в правилах верхнего уровня.

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `server` | string -> dns server | — (обязательно) | Сервер запроса; не `fakeip` (ошибка `check`). Несуществующий тег `check` и запуск пропускают: на запросе — `transport not found` в логе, правило пропускается, а у `evaluate` без `tag` прежний анонимный ответ сбрасывается. |
| `tag` | string | — | Имя сохранённого ответа; на него ссылаются через `match_response: "<tag>"`. Без тега ответ «анонимный»: `match_response: true` видит последний такой. Повтор тега — ошибка `check` (`duplicate evaluate tag`). Неиспользуемый тег и анонимный ответ, перезаписанный до использования, — предупреждения. |
| `speculative` | bool | `false` | Отправить запрос, не дожидаясь предшествующих `race`-правил. |
| параметры маршрутизации | | | См. таблицу выше. |

Правило с `match_response` или полями ответа требует предшествующего правила верхнего уровня с `evaluate`; собственный `evaluate` того же правила не считается (сопоставление идёт до выполнения действия). Иначе `check`: `response-based matching requires a preceding evaluate action` или `undefined evaluate tag: X`.

### `respond`

С 1.14. Вернуть клиенту сохранённый ответ `evaluate`, без нового запроса, и завершить перебор. Полей нет. Отдаётся ответ по тегу из `match_response` этого правила, иначе последний анонимный. Требует предшествующего `evaluate` (иначе ошибка `check`); если во время работы ответа нет, запрос завершается ошибкой, а не переходит к следующим правилам.

### `route-options`

Изменить параметры маршрутизации для дальнейших правил и продолжить перебор. Поля — параметры маршрутизации (`server` нет). Все пустые — ошибка разбора `empty DNS route option action`. Лишние ключи молча отбрасываются.

### `reject`

Отклонить запрос и завершить перебор.

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `method` | string | `default` | `default` — ответить REFUSED; `drop` — не отвечать. `reply` в DNS-правилах запрещён (ошибка `check`). |
| `no_drop` | bool | `false` | Отключить автоматический переход на `drop` после 50 срабатываний за 30 с. С `method: drop` — ошибка разбора `no_drop is not available in current context` (проверено). По коду этот счётчик работает только для внутренних разрешений; клиентский запрос при `method: default` получает REFUSED всегда. |

Лишние ключи (например, `server`) молча отбрасываются. При внутреннем разрешении `reject` даёт ошибку разрешения.

### `predefined`

С 1.12. Ответить заранее заданными записями и завершить перебор (замена legacy-сервера `rcode://`).

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `rcode` | string\|int | `NOERROR` | Код ответа ([формат](#формат-dns-записей-и-кодов-ответа)). |
| `answer` | string\|[string] | — | Записи секции Answer. |
| `ns` | string\|[string] | — | Записи секции Authority. |
| `extra` | string\|[string] | — | Записи секции Additional. |

При внутреннем разрешении используются только A/AAAA из `answer`; код, отличный от NOERROR, — ошибка разрешения.

### `race` и `speculative`

С 1.14. По умолчанию правила строго последовательны: правило с `match_response` ждёт свои ответы `evaluate`, и следующие правила не рассматриваются, пока оно не решено. Правило с `race` порядок не держит: перебор идёт дальше, пока его ответы в пути; каждое `race`-правило решается, когда его ответы готовы, и первое совпавшее немедленно завершает перебор, отменяя остальные запросы. Правила без `race` всё равно срабатывают в порядке списка: их действие ждёт, пока не станет ясно, что ни одно предшествующее `race`-правило не совпало. `speculative` у `route`/`evaluate` разрешает отправить запрос сразу, параллельно ожиданию `race`-правил (ответ может пропасть впустую). Любое из этих полей включает новый режим.

Исходники: dns/router.go (walkDNSRules, sweepArmedDNSRules, launchDNSEvaluate, validateLegacyDNSModeDisabledRules), dns/router_race_test.go.

## Режимы DNS-правил: legacy и новый

В 1.14 правила работают в одном из двух режимов на весь конфиг; режим выбирается при создании (`box.New`, то есть уже на `check`) и заново при запуске (`dns/router.go`, `dnsRuleModeFlags`).

Признаки legacy-режима (флаг `needed`), в любом правиле, включая вложенные:
- `ip_cidr`, `ip_is_private` или `ip_accept_any` без `match_response`;
- `rule_set_ip_cidr_accept_empty`;
- `rule_set`, ссылающийся на rule-set с правилами `ip_cidr` (если не задан `rule_set_ip_cidr_match_source`);
- непустой `strategy` в действии `route`, `evaluate` или `route-options` (флаг `neededFromStrategy`).

Признаки нового режима (флаг `disabled`):
- `match_response`, любое поле `response_*`;
- действие `evaluate` или `respond`;
- `ip_version`, `query_type`, либо rule-set с `query_type`;
- `race`, `speculative`, `disable_optimistic_cache` в действии.

Выбор: есть признак нового режима и `strategy` в действии — ошибка `check` (`Legacy strategy DNS rule action option is deprecated…`). Есть признак нового режима — новый режим, и тогда адресные поля без `match_response` дают ошибку `check` (`Response Match Fields (…) require match_response to be enabled`), rule-set только из `ip_cidr` без `match_response` — `Legacy Address Filter Fields in DNS rules is deprecated…` (по коду даже при `rule_set_ip_cidr_match_source: true`), `rule_set_ip_cidr_accept_empty` — своя ошибка. Иначе есть признак legacy — legacy-режим с предупреждениями в логе: `legacy-dns-address-filter` и `legacy-dns-rule-strategy` сообщаются только при запуске (`Router.Start`), `check` их не выводит (проверено: `ip_cidr` без `match_response` и `strategy` в действии дают код 0 без единой строки); WARN о `rule_set_ip_cidr_accept_empty` виден уже на `check`. Нет ни того ни другого — новый режим.

| | Новый режим | Legacy-режим |
|---|---|---|
| Адресные поля (`ip_cidr`, `ip_is_private`, `ip_accept_any`) | Только с `match_response` — к ответу `evaluate`. | Фильтр: правило сопоставляется без них, запрос уходит на его сервер, ответ проверяется; при несовпадении перебор продолжается со следующего правила новым запросом. Такие правила действуют только на запросы A/AAAA/HTTPS. |
| `evaluate`, `respond`, `race`, `speculative` | Есть. | Недоступны (сами включают новый режим). |
| `ip_version`, `query_type` | Действуют и на внутренние разрешения (A и AAAA резолвятся раздельно, каждый своим проходом по правилам). | Недоступны. |
| `strategy` в действии | Недоступно. | Действует на запрос. |
| Кэш отвергнутых ответов | — | `experimental.cache_file.store_rdrc` (устарело в 1.14). |

Миграция с legacy: вместо фильтра адресов — `{"action": "evaluate", "server": "remote"}`, затем `{"match_response": true, "rule_set": "geoip-xx", "server": "local"}`, затем правило или `final` на `remote`. Раздела миграции для `strategy`, на который ссылается сообщение об ошибке (`#migrate-dns-rule-action-strategy-to-rule-items`), в документации 1.14 нет; по смыслу замена — правила по `query_type`/`ip_version` (например, `{"query_type": "AAAA", "action": "predefined"}` — пустой NOERROR вместо `ipv4_only`) или `domain_resolver.strategy`/`dns.strategy`.

Метаданные rule-set: у `local`/`inline` они известны уже на `check`, у `remote` — только после загрузки при запуске. Поэтому ссылка на удалённый rule-set только из `ip_cidr` без `match_response` в новом режиме проходит `check`, а запуск падает. Обновление удалённого rule-set, которое сменило бы режим, во время работы отвергается.

Исходники: dns/router.go (resolveLegacyDNSMode, dnsRuleModeRequirements*, validateLegacyDNSModeDisabled*, ValidateRuleSetMetadataUpdate, exchangeLegacy, matchDNS, lookupWithRules), route/rule/rule_dns.go (LegacyPreMatch, MatchAddressLimit, WithAddressLimit), experimental/deprecated/constants.go, docs/migration.md.

## Проверка: что ловит `sing-box check`, а что только запуск

`check` выполняет `box.New` без запуска: разбор, создание серверов, построение правил. Всё, что разрешается на стадиях запуска (зависимости серверов, `final`, эндпоинты, `preferred_by`, `detour`), он не видит. Проверено командой `check` 1.14.2; столбец «Запуск» — по коду (запуск в этой работе не выполнялся).

| Ситуация | `check` | Запуск / работа |
|---|---|---|
| Сервер без `type` / legacy `address`, блок `dns.fakeip` | ошибка | — |
| Неизвестный `type`, неизвестный ключ, `type`/`tag`/условие не в нижнем регистре | ошибка | — |
| Два сервера с одним `tag` | проходит | Проходит; остаётся последний. |
| `final` на несуществующий тег | проходит | `default DNS server not found: X` |
| `fakeip` первым при пустом `final` или в `final`; два `fakeip`; `fakeip` без диапазонов | ошибка | — |
| Доменный `server` без `domain_resolver` и без `detour` | ошибка | — |
| `domain_resolver` на несуществующий сервер / цикл | проходит | `dependency[X] not found for server[Y]` / `circular server dependency` |
| `detour` на несуществующий исходящий | проходит | `udp`/`tcp`/`tls`/`quic`/`https`/`h3`: `outbound detour not found`; `local`/`dhcp`: ошибка на каждом запросе. |
| `detour` на пустой direct | проходит | `detour to an empty direct outbound makes no sense` (те же типы; `local`/`dhcp` — на запросе). |
| `resolved` на Windows | ошибка | — |
| `tailscale`/`openvpn`/`openconnect` без `endpoint` | ошибка | — |
| … с несуществующим или чужим `endpoint` | проходит | `endpoint not found` / `endpoint is not …` |
| `h3` с `utls`/`reality` | ошибка | — |
| `quic` с `utls` | проходит | ожидается ошибка соединения (не проверено) |
| `neighbor_domain` без ведущей точки | ошибка | — |
| `route`/`evaluate` без `server` | ошибка | — |
| `route`/`evaluate` на несуществующий сервер | проходит | Запуск проходит; `transport not found` в логе на запросе, правило пропускается. |
| `preferred_by` на несуществующий сервер или неподходящий тип | проходит | `DNS server not found` / `does not support preferred_by` |
| `rule_set` на несуществующий rule-set | ошибка | — |
| Удалённый rule-set только из `ip_cidr` без `match_response` в новом режиме | проходит | ошибка legacy address filter |
| Конфликты режимов, `match_response` без `evaluate`, неизвестный тег ответа, `race` без `match_response`, `race` + `speculative`, `client_subnet` + `remove_client_subnet`, `reject` с `reply`, `evaluate` на `fakeip`, `optimistic` + `disable_cache`/`disable_expire` | ошибка | — |
| DNS-правило с `outbound` | ошибка (фатальное устаревание) | С `ENABLE_DEPRECATED_OUTBOUND_DNS_RULE_ITEM=true` работает. |
| Два и более DNS-сервера, а исходящий резолвит домен сам (любой `direct`, исходящий с доменным `server` без `detour`) и не имеет своего `domain_resolver`, и нет `route.default_domain_resolver` | ошибка (фатальное устаревание `missing route.default_domain_resolver or domain_resolver`) | С `ENABLE_DEPRECATED_MISSING_DOMAIN_RESOLVER=true` — предупреждение. Если исходящих нет вовсе, неявный direct создаётся только при запуске — по коду запуск тогда завершится той же фатальной ошибкой. |

Фатальные устаревания: в 1.14.2 функция, чьё удаление было назначено на 1.14, завершает `check`/запуск с `FATAL … set environment variable ENABLE_DEPRECATED_<ИМЯ>=true`; назначенные на 1.16 дают только предупреждение.

Исходники: cmd/sing-box/cmd_check.go, box.go (New, Start), dns/transport_manager.go (Start, startTransports, Create), common/dialer/dialer.go (NewDNSQueryOptions), common/dialer/detour.go, experimental/deprecated/stderr.go, experimental/deprecated/constants.go, route/rule/rule_item_preferred_by_dns.go.

## Windows: сводка особенностей

- Нет: сервер `resolved` (ошибка `check`); neighbor resolver, а с ним `neighbor_domain`, `source_mac_address`, `source_hostname`; условия `user`, `user_id`, `package_name*`, `network_is_*`, `network_interface_address` (принимаются, не срабатывают); `network_type` не определяется (по коду `wifi` совпадает всегда, остальное никогда); Dial Fields `routing_mark` и `bind_address_no_port` (ошибка `check`), `netns`, `protect_path`.
- Есть: `process_name`, `process_path` (путь `C:\…`), `process_path_regex`, `interface_address`, `default_interface_address`, `wifi_ssid`/`wifi_bssid` (с 1.13, WLAN API); серверы `dhcp`, `quic`, `h3`, `tailscale`, `openvpn`, `openconnect` в официальной сборке.
- `local` на Windows сам опрашивает DNS-серверы адаптеров по UDP (подробно в [разделе local](#сервер-local)); `prefer_go` ни на что не влияет; `*.local` — через встроенный mDNS.
- Путь hosts по умолчанию — `<системный каталог>\drivers\etc\hosts`; переменные в `path` — только `$VAR`.
- TUN с `dns_mode: hijack` (по умолчанию с 1.14) выставляет DNS интерфейса, а при `strict_route` ставит фильтры WFP ([inbounds.md](inbounds.md)).

Исходники: release/DEFAULT_BUILD_TAGS_WINDOWS, service/resolved/stub.go, route/neighbor_resolver_stub.go, dns/transport/local/systemconfig/source_windows.go, dns/transport/hosts/hosts_windows.go, common/dialer/default.go, common/settings/wifi_windows.go, route/network.go (`needWIFIState`, `DefaultNetworkInterface`), route/rule/rule_item_network_type.go, docs/changelog.md (1.13.0, пункт 6; 1.14.0, пункт 19).

## Заметки для tray-sing-box

- В секции `dns` `configfile/dependency.go` проверяет только `detour` серверов (ссылку на несуществующий исходящий) и `rule_set` DNS-правил (его отвергает и сам `check`; приложение лишь даёт понятное сообщение). Остальные случаи «`check` проходит — запуск падает» из [таблицы проверки](#проверка-что-ловит-sing-box-check-а-что-только-запуск) (`dns.final`, `domain_resolver`, `preferred_by`, `detour` на пустой direct, эндпоинты, `server` правила на несуществующий сервер) приложение не проверяет ни при какой записи конфига. Страница настроек секцию `dns` не редактирует, но такая секция может прийти с первым конфигом, откатом истории или ручной правкой.
- `ENABLE_DEPRECATED_OUTBOUND_DNS_RULE_ITEM`, `ENABLE_DEPRECATED_MISSING_DOMAIN_RESOLVER` и `ENABLE_DEPRECATED_LEGACY_DOMAIN_STRATEGY_OPTIONS` доходят до sing-box: `process.SingBoxEnv` пропускает из окружения приложения все переключатели `ENABLE_DEPRECATED_*` с булевым значением (`process/env_windows.go`). Без них соответствующие конфиги в 1.14.2 не проходят `check` и не запускаются.
- Конфиг с двумя DNS-серверами и direct-исходящим (или узлами с доменным `server`) без `route.default_domain_resolver` в 1.14.2 не проходит `check`.
- Ключ `path` у сервера `hosts` задаёт файл, который читает sing-box с правами администратора; guard приложения запрещает добавлять такой `path` (разрешён только путь URL у DoH/H3).

## Расхождения документации и кода

1. `docs/configuration/dns/index.md`: у `independent_cache` сказано «будет удалён в 1.14.0»; по коду удаление назначено на 1.16.0, в 1.14.2 поле принимается с предупреждением и ничего не делает.
2. Там же таблица полей называет ключ `server` вместо `servers`.
3. `server/fakeip.md`: заголовок поля `inet6_address`, в коде `inet6_range`. Значения диапазонов в примере — не значения по умолчанию: по коду умолчаний нет, нужен хотя бы один диапазон.
4. У `https`/`h3` в коде есть поле `method` (в документации нет, кодом не используется — всегда POST).
5. `dhcp` и `mdns` принимают `prefer_go` и `neighbor_domain` (наследуют структуру `local`) — не документировано, не используется. Документация `mdns` перечисляет Dial Fields, но код их не использует (кроме `domain_resolver` как зависимости).
6. `rule.md`, таблица `preferred_by`: нет `openvpn`, хотя код его поддерживает. Changelog 1.14 заявляет поддержку `dhcp` — в коде её нет (ошибка запуска).
7. Changelog 1.14 упоминает DNS-условия `domain_label_count` и `search_domain_available` — их нет ни в коде, ни в остальной документации.
8. `rule.md`: `outbound` «будет удалён в 1.14.0» — в 1.14.2 поле ещё разбирается; без `ENABLE_DEPRECATED_OUTBOUND_DNS_RULE_ITEM=true` фатально.
9. Комментарий в `option/rule_dns.go` называет `rule_set_ip_cidr_accept_empty` удалённым в 1.11.0; на деле он работает в legacy-режиме и устарел в 1.14 (удаление 1.16) — документация здесь права.
10. Сообщение об ошибке legacy `strategy` ведёт на `migration/#migrate-dns-rule-action-strategy-to-rule-items`, такого раздела в `migration.md` нет.
11. `rule.md` помечает `action` обязательным; по коду по умолчанию `route`.
12. `rule.md` связывает требование `match_response` для `ip_cidr`/`ip_is_private`/`ip_accept_any` с использованием `evaluate` или полей ответа; по коду оно действует на весь конфиг, как только выбран новый режим (любой его признак в любом правиле).
13. `rule_action.md`, `no_drop`: переход на `drop` после 50 срабатываний за 30 с по коду применяется только к внутренним разрешениям, клиентский запрос при `method: default` всегда получает REFUSED (вывод из кода, не проверялся при работе).
14. По коду rule-set только из `ip_cidr` в новом режиме отвергается и при `rule_set_ip_cidr_match_source: true`, хотя тогда адреса сравниваются с источником и ответ не нужен (похоже на недосмотр; документация этого не оговаривает).
15. Документация `index.md` («пусто — первый сервер») не упоминает, что первый сервер типа `fakeip` при пустом `final` — ошибка.
16. `rule_set_ipcidr_match_source` (старое имя, «удалено в 1.11») отвергается кодом только при непустом `rule_set`; в правиле без `rule_set` ключ принимается и ничего не делает (проверено `check`).

## Исходники

option/dns.go, option/rule_dns.go, option/rule_action.go, option/rule_nested.go, option/dns_record.go, option/types.go (DomainStrategy, DNSQueryType, InterfaceType), option/outbound.go (DialerOptions), option/tailscale.go, option/resolved.go, option/openconnect.go, option/openvpn.go, constant/dns.go, constant/timeout.go, include/registry.go, include/*_stub.go, box.go, cmd/sing-box/cmd_check.go, dns/router.go, dns/client.go, dns/transport_manager.go, dns/transport_adapter.go, dns/transport_dialer.go, dns/extension_edns0_subnet.go, dns/transport/{udp,tcp,tls,https,https_transport,multiplexer}.go, dns/transport/{local,hosts,fakeip,dhcp,mdns,quic}/, dns/transport/local/systemconfig/, route/rule/rule_dns.go, route/rule/rule_action.go, route/rule/rule_abstract.go, route/rule/rule_nested_action.go, route/rule/rule_item_*.go, route/router.go, route/network.go, route/neighbor_resolver_stub.go, common/dialer/dialer.go, common/dialer/detour.go, protocol/direct/outbound.go, protocol/tailscale/dns_transport.go, protocol/openvpn/dns_transport.go, protocol/openconnect/dns_transport.go, service/resolved/transport.go, service/resolved/stub.go, experimental/deprecated/constants.go, experimental/deprecated/stderr.go; документация: docs/configuration/dns/**, docs/migration.md, docs/deprecated.md, docs/changelog.md.
