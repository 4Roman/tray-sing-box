# sing-box 1.14.2: командная строка

Справочник по `sing-box.exe` версии 1.14.2 (стабильная, 24.09.2026): все команды и флаги, как читается и сливается конфиг, что делают `check` и `format`, коды завершения, сигналы, переменные окружения и то, как всем этим пользуется tray-sing-box. Поля самого конфига описаны в соседних файлах: [config.md](config.md) (верхний уровень, `log`, `ntp`, `certificate`), [inbounds.md](inbounds.md), [outbounds.md](outbounds.md), [shared.md](shared.md), [dns.md](dns.md), [route.md](route.md), [experimental.md](experimental.md), [deprecations.md](deprecations.md).

Всё, что помечено «проверено», запускалось на официальной сборке `sing-box-1.14.2-windows-amd64` (Go 1.26.8, `CGO: disabled`, теги `with_gvisor, with_quic, with_dhcp, with_wireguard, with_utls, with_acme, with_clash_api, with_tailscale, with_ccm, with_ocm, with_cloudflared, with_naive_outbound, with_purego, with_usbip, with_openvpn, with_openconnect, badlinkname, tfogo_checklinkname0`; `with_v2ray_api` в неё НЕ входит). Командная строка построена на `spf13/cobra` v1.10.2.

## Сводка команд

| Команда | Что делает | Читает конфиг | Сеть | Замечания |
|---|---|---|---|---|
| `run` | запускает сервис | да | да | единственная команда, которая поднимает inbounds, TUN и слушатели из конфига (из прочих слушает только `api openconnect auth`: локальный порт для SSO) |
| `check` | проверяет конфиг: разбор + `box.New` без запуска | да | нет | см. [check](#check) |
| `format` | переформатирует каждый файл конфига по отдельности | да (без `box.New`) | нет | `-w` пишет обратно |
| `merge <output-path>` | сливает конфиги в один файл, встраивает содержимое файлов сертификатов/ключей | да | нет | |
| `version` | печатает версию, Go, теги сборки | нет | нет | `-n` — только номер |
| `schema` | печатает JSON Schema конфига для этой сборки | нет | нет | с 1.14 |
| `generate …` | генераторы: uuid, случайные байты, пары ключей | нет | нет | |
| `rule-set …` | компиляция, декомпиляция, проверка, слияние rule-set | нет (свои файлы) | нет | |
| `geoip …`, `geosite …` | чтение устаревших баз `geoip.db` / `geosite.db`, экспорт в rule-set | нет (свои файлы) | нет | сами базы удалены из конфига в 1.12 |
| `tools …` | «экспериментальные» сетевые утилиты через outbound из конфига | да (или пустой) | да | поднимает outbounds/DNS/router, но не inbounds |
| `api …` | клиент gRPC-сервиса `api` работающего экземпляра | нет | да (к сервису) | с 1.14; нужен запущенный sing-box с сервисом `api` |
| `completion <shell>` | скрипт автодополнения (bash, fish, powershell, zsh) | нет | нет | генерируется cobra |
| `help [команда]` | справка | нет | нет | то же, что `-h` |
| `netns-holder` | скрытая служебная команда для сетевых пространств Linux | нет | нет | запускается самим sing-box |

Без аргументов `sing-box` печатает справку и завершается с кодом 0.

Исходники: cmd/sing-box/cmd.go, cmd/sing-box/main.go и файлы cmd/sing-box/cmd_*.go.

## Глобальные флаги

Флаги объявлены на корневой команде как persistent: их можно писать и до, и после имени подкоманды (`sing-box -D dir check` и `sing-box check -D dir` равнозначны, проверено). Исключение — `api`: там разбор флагов cobra отключён, см. [api](#api).

| Флаг | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `-c`, `--config` | string, повторяемый | — | путь к файлу конфига. Можно указать несколько раз. Особое значение — буквально `stdin` (не `-`: `-c -` ищет файл с именем `-`, проверено) |
| `-C`, `--config-directory` | string, повторяемый | — | каталог: берутся все файлы с суффиксом `.json` (регистр суффикса важен, `A.JSON` пропускается даже на Windows, проверено), без рекурсии, подкаталоги пропускаются |
| `-D`, `--directory` | string | — (текущий каталог) | рабочий каталог: перед чтением конфига процесс делает в него `chdir`; если каталога нет, он создаётся (`MkdirAll`, проверено) |
| `--disable-color` | bool | `false` | убирает ANSI-цвета из вывода служебного логгера (ошибки CLI, предупреждения об устаревании) и, в `run`, из лога самого сервиса |
| `-h`, `--help` | bool | `false` | справка по команде |

Если не задан ни `-c`, ни `-C`, используется `config.json` в рабочем каталоге (после `-D`). Флаги `-c` и `-C` можно сочетать.

Всё перечисленное (`chdir` по `-D`, создание каталога, служебный логгер без цвета, менеджер устаревания) делает общий хук `preRun` корневой команды. У групп `geoip` и `geosite` есть собственный `PersistentPreRun` (открытие базы), а cobra 1.10 без `EnableTraverseRunHooks` выполняет только ближайший хук, поэтому для их подкоманд `preRun` не вызывается: `-D` и `--disable-color` там молча не действуют, файл `-f` ищется от текущего каталога процесса (по коду, не запускалось).

Исходники: cmd/sing-box/cmd.go, cmd/sing-box/cmd_geoip.go, cmd/sing-box/cmd_geosite.go.

## Откуда берётся конфиг

Все команды, работающие с конфигом сервиса (`run`, `check`, `format`, `merge`, `tools`), читают его одной и той же функцией. Команды `rule-set …` читают свои файлы отдельно.

### Пути: -c, -C, stdin и config.json по умолчанию

- Сначала читаются все `-c` в порядке флагов, затем содержимое каждого `-C`.
- Список файлов затем **сортируется по строке пути** (побайтово). Порядок флагов на результат не влияет; на порядок влияют только имена (отсюда совет давать файлам числовые префиксы). Путь сравнивается в том написании, в каком получен: `-c m/b.json` и найденный через `-C m` файл `m\a.json` сравниваются как строки с разными разделителями.
- Каждый файл разбирается **самостоятельно и полностью**, как целый конфиг: неизвестное поле, неверный тип, outbound без `type` в любом файле — ошибка `decode config at <путь>: …`. Фрагмент, который «сам по себе» не является корректным конфигом, не допускается.
- `-c stdin` читает стандартный ввод до конца.
- Один и тот же файл, указанный дважды (например, через `-c` и через `-C`), попадёт в слияние два раза и даст ошибку дубликата тега (проверено).
- Пустой список (например, `-C` на каталог без `.json`) — ошибка `unmarshal merged config: EOF`.

Исходники: cmd/sing-box/cmd_run.go (`readConfigAt`, `readConfig`).

### Слияние нескольких файлов

Если файл один, он используется как есть. Если файлов несколько, их исходные тексты сливаются по очереди (`badjson.MergeJSON`) в порядке сортировки, а результат разбирается ещё раз как единый конфиг. Правила (проверено на `merge`, `check`):

| Что совпало | Результат |
|---|---|
| объекты с одинаковым ключом | сливаются рекурсивно, ключ за ключом |
| массивы (`inbounds`, `outbounds`, `route.rules`, …) | конкатенируются в порядке файлов; элементы по `tag` НЕ сопоставляются |
| скаляры с одинаковым ключом | **побеждает значение из более раннего файла** (по сортировке). Пример: `00-base.json` c `"level":"info"` и `99-override.json` с `"level":"debug"` дают `info` |
| одинаковый `tag` в разных файлах | после слияния — ошибка `duplicate outbound/endpoint tag` (или `duplicate inbound tag`) |
| ключи в разном регистре (`log` / `Log`) | слияние сравнивает ключи с учётом регистра и оставляет оба; затем при разборе они попадают в одно поле: у скаляров выигрывает тот, что стоит позже в тексте, а вложенные объекты сливаются поле за полем (проверено: `{"log":{"level":"bogus"},"Log":{"timestamp":true}}` даёт `level: bogus` и `timestamp: true`) — избегайте |

Комментарии при слиянии нескольких файлов теряются (см. [merge](#merge)).

Исходники: cmd/sing-box/cmd_run.go (`mergeOptionsList`), библиотека github.com/sagernet/sing/common/json/badjson.

### Синтаксис файла: JSON с комментариями

Конфиг — JSON, разбираемый расширенным декодером `github.com/sagernet/sing/common/json` (`UnmarshalExtendedContext`). Проверено на 1.14.2:

| Конструкция | Принимается |
|---|---|
| `// …` до конца строки | да |
| `/* … */` | да (без вложенности: закрывается на первом `*/`) |
| `# …` до конца строки | да |
| `//` внутри строкового значения | не комментарий, остаётся частью строки |
| висячая запятая после последнего элемента объекта или массива | да |
| одинарные кавычки, ключи без кавычек | нет |
| UTF-8 BOM в начале файла | **нет**: `invalid character 'ï' looking for beginning of value` |
| пустой файл | нет: `unexpected end of JSON input` |
| второй JSON-документ после первого | нет: `invalid character … after top-level value` |
| число строкой (`"listen_port": "2080"`) | нет, ошибка типа |
| `null` вместо объекта (`"log": null`) | да, как отсутствие |

Комментарии запоминаются декодером (`json.CommentSet` в `option.Options`) и с 1.14.0 сохраняются командой `format`.

Исходники: option/options.go (`UnmarshalJSONContext`, `Comments`, `SetComments`), cmd/sing-box/cmd_run.go.

### Сопоставление ключей и неизвестные поля

Корневой объект разбирается с `DisallowUnknownFields`, так же — вложенные объекты, если у типа нет собственного нестрогого декодера. Декодер — форк `encoding/json` Go из библиотеки sing, и сопоставление ключей унаследовано от него. Полные правила (проверено на 1.14.2) — в [config.md](config.md#разбор-json): [строгость](config.md#строгость-неизвестные-поля), [регистр ключей](config.md#регистр-ключей), [повторяющиеся ключи](config.md#повторяющиеся-ключи). Коротко:

- Обычные поля сопоставляются без учёта регистра, с простым свёртыванием Unicode: `"LOG"`, `"Outbounds"`, `"Server_Port"`, `"Detour"` работают как `log`, `outbounds`, `server_port`, `detour`; ключ `"networK"` (последняя буква — KELVIN SIGN U+212A) — это `network`, `"ſerver"` (первая буква — LONG S U+017F) — `server`.
- «Головные» ключи двухпроходных объектов (`type`, `tag` и другие общие поля) нужно писать в точном виде: `"Type"` или `"TAG"` в outbound/inbound, `"Tag"` у DNS-сервера, `"Type"` или `"Domain"` в правиле маршрутизации дают `json: unknown field` (проверено). Какие объекты так устроены — в [config.md](config.md#регистр-ключей).
- Повтор ключа — не ошибка: у скалярного значения побеждает последний, в том числе при разном регистре (`{"Level":"bogus","level":"info"}` проходит, обратный порядок — ошибка уровня лога); повторённый объект не заменяет первый, а дописывается в него поле за полем (проверено).
- Не везде неизвестное поле — ошибка: у типов со своим `UnmarshalJSON` на обычном `json.Unmarshal` строгость теряется. Пример (проверено): лишний ключ в правиле с `"action": "reject"` принимается молча, а в правилах `route`, `sniff`, `hijack-dns` — ошибка `unknown field`.
- Сгенерированная JSON Schema (см. ниже) строже рантайма: она чувствительна к регистру и запрещает лишние свойства, поэтому редактор подсветит `"Detour"`, который sing-box примет.

Для tray-sing-box это означает: свёртка регистра в `configfile/guard.go` (`foldKey`) и в проверке зависимостей — осознанное завышение. Для «головных» ключей sing-box сам отвергает вариант в другом регистре, для остальных полей свёртка совпадает с рантаймом.

Исходники: option/options.go, option/outbound.go, option/inbound.go, option/endpoint.go, option/service.go, option/dns.go, option/rule.go, option/rule_action.go, option/rule_dns.go, option/rule_set.go; библиотека github.com/sagernet/sing/common/json (поведение установлено по бинарнику; исходник библиотеки разобран в config.md).

### Ключ $schema и команда schema

С 1.14.0 в корне конфига допустим ключ `$schema` (string, по умолчанию пусто). Рантайм его игнорирует, он нужен редакторам. Опубликованная схема: `https://sing-box.sagernet.org/schema.json`. Можно указать и локальный файл (`"$schema": "./schema.json"`, проверено `check`).

`sing-box schema [-o <файл>]` генерирует JSON Schema (Draft 2020-12, `$id` = `https://sing-box.sagernet.org/schema.json`, корень `additionalProperties: false`) для типов, вкомпилированных в эту сборку. Флаги: `-o`, `--output` (string, по умолчанию пусто — вывод в stdout; иначе запись в файл с правами 0644). Проверено: схема из Windows-сборки 1.14.2 совпадает с `docs/schema.json` репозитория побайтно, за исключением концов строк.

| Поле | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `$schema` | string | `""` | URI схемы для редактора; на работу не влияет. С 1.14.0 |

Исходники: cmd/sing-box/cmd_schema.go, option/options.go (`DescribeSchema`), schema/.

## Рабочий каталог и относительные пути

- `-D` меняет рабочий каталог процесса **до** чтения конфига, поэтому относительный `-c` ищется внутри `-D` (`sing-box -D m check -c a.json` читает `m/a.json`, проверено).
- Все относительные пути внутри конфига разрешаются относительно рабочего каталога процесса. В CLI у `filemanager.BasePath` нет базового каталога (он есть только у мобильных и десктопных клиентов через libbox). Это касается `log.output`, `experimental.cache_file.path` (по умолчанию `cache.db`), `path` локальных rule-set, файлов сертификатов и ключей TLS, `private_key_path` SSH, `external_ui` Clash API, каталогов состояния Tailscale и т. п.
- Часть путей перед использованием проходит через `os.ExpandEnv`: подставляются `$VAR` и `${VAR}` (синтаксис `%VAR%` Windows НЕ раскрывается). Список: `private_key_path` у SSH outbound (и в `merge`), `data_directory` у ACME (TLS и service `acme`), Cloudflare Origin CA, `path` у DNS-сервера `hosts`, `external_ui` Clash API, `masquerade` (`directory`) у hysteria2 inbound, `state_directory` и `taildrop_directory` у Tailscale, `data_directory` у tor, `dashboard.path` у service `api`, `config_path` у service `derp`. Знак `$` в таких путях — спецсимвол.
- Без `-D` рабочий каталог наследуется от родительского процесса.

Исходники: cmd/sing-box/cmd.go (`preRun`), constant/path.go, protocol/ssh/outbound.go, common/tls/acme.go, service/acme/service.go, service/origin_ca/service.go, dns/transport/hosts/hosts.go, experimental/clashapi/server.go, protocol/hysteria2/inbound.go, protocol/tailscale/endpoint.go, protocol/tor/outbound.go, service/api/dashboard.go, service/derp/service.go.

## run

`sing-box [глобальные флаги] run` — единственная команда, которая запускает сервис. Своих флагов нет. Валидатора аргументов у `run` нет, и лишние позиционные аргументы cobra, по её правилам для команды без подкоманд, молча игнорирует (по коду, не запускалось). Последовательность:

1. Прочитать и слить конфиги ([выше](#откуда-берётся-конфиг)).
2. Только Linux: если в `network_namespaces` есть тип `unshare`, а у процесса нет `CAP_SYS_ADMIN`, sing-box перезапускает сам себя в новом user namespace (`/proc/self/exe`) и выходит с кодом дочернего процесса.
3. `box.New` (построение всех компонентов). При ошибке: `FATAL create service: …`, код 1.
4. `Start` (логгер, кэш-файл, DNS, outbounds, rule-set, inbounds, services, …). При ошибке: `FATAL start service: …`, код 1. Если во время запуска пришёл сигнал остановки, запуск прерывается. Если он не завершится за 10 с (`C.FatalStopTimeout`), процесс завершается с `FATAL sing-box did not close!`.
5. Ждать сигнала.

Исходники: cmd/sing-box/cmd_run.go, cmd/sing-box/cmd_run_userns_linux.go, cmd/sing-box/cmd_run_userns_other.go, box.go.

### Сигналы, перезагрузка и остановка

`run` подписан на `os.Interrupt`, `SIGTERM` и `SIGHUP`:

| Сигнал | Действие |
|---|---|
| `os.Interrupt` (Ctrl+C), `SIGTERM` | `Close` всех компонентов и выход с кодом 0. Ошибки закрытия пишутся как `ERROR sing-box did not closed properly`, код всё равно 0. Если `Close` висит больше 10 с — `FATAL sing-box did not close!`, код 1 |
| `SIGHUP` (только Unix) | «перезагрузка»: конфиг перечитывается и прогоняется через ту же проверку, что `check`. При ошибке старый экземпляр продолжает работать (`ERROR reload service: …`). При успехе старый экземпляр закрывается, конфиг читается ещё раз и запускается новый; если новый не стартует, процесс завершается с кодом 1 |

На Windows `SIGHUP` не приходит никогда, и перезагрузки нет: новый конфиг применяется только перезапуском процесса. Ctrl+C и Ctrl+Break в консоли приходят как `os.Interrupt`, закрытие окна консоли рантайм Go превращает в `SIGTERM` (у процесса есть несколько секунд, потом система его завершает). События выхода из системы и выключения (`CTRL_LOGOFF_EVENT`, `CTRL_SHUTDOWN_EVENT`) Windows доставляет только службам; обычный консольный процесс их не получает и просто завершается системой — в проекте это и наблюдается: при выключении Windows sing-box со скрытой консолью убивается без корректного завершения (код 0x40010004). Процесс, убитый через `TerminateProcess` (так делают диспетчер задач и tray-sing-box), `Close` не выполняет вовсе.

Исходники: cmd/sing-box/cmd_run.go (`run`, `create`, `closeMonitor`), constant/timeout.go.

### Куда пишется лог

Поля `log` описаны в [config.md](config.md). Здесь — что из них следует для процесса.

| Настройка | Куда идёт вывод | Цвет | Метка времени |
|---|---|---|---|
| нет `log` или `output` пуст | stderr | ANSI-цвета **всегда**, даже если stderr перенаправлен в файл (только `--disable-color` их убирает) | `[NNNN]`: секунды с момента старта; при `timestamp: true` — полная дата `-0700 2006-01-02 15:04:05` |
| `output: "stderr"` / `"stdout"` | соответствующий поток | как выше | как выше |
| `output: "<путь>"` | файл, дописывание (`O_APPEND`), создаётся с правами 0644; относительный путь — от рабочего каталога; открывается при `Start`, не в `box.New` | без цвета | без метки, если `timestamp` не `true` |
| `disabled: true` | никуда | — | — |

- Уровень по умолчанию, если `level` не задан, — **`trace`** (самый подробный). Допустимые значения: `trace`, `debug`, `info`, `warn` (или `warning`), `error`, `fatal`, `panic`. Документация умолчание не называет, значение взято из кода.
- Сообщения самого CLI (`FATAL decode config …`, `FATAL create service …`, предупреждения об устаревании) идут через отдельный служебный логгер **всегда в stderr**, независимо от `log.output`. Ошибку конфига поэтому не найти в файле `log.output`, она будет в перехваченном stderr.
- Записи, сделанные до старта логгера, копятся в буфере и выводятся при `Start`. `check` логгер не запускает, поэтому предупреждения компонентов при `check` не видны.

Исходники: log/log.go, log/observable.go, log/format.go, log/level.go, log/export.go, cmd/sing-box/cmd.go.

## check

`sing-box [глобальные флаги] check` — без позиционных аргументов (лишний аргумент — ошибка `unknown command`, код 1). Флагов нет. Читает и сливает конфиг так же, как `run`, вызывает `box.New` и сразу `Close`, **не вызывая `Start`**. Успех: ничего не печатает, код 0 (предупреждения об устаревании при этом выводятся в stderr). Ошибка: одна строка `FATAL …` в stderr, код 1.

Форматы сообщений: ошибка разбора — `decode config at <путь>: <путь.в.json>: …`, ошибка слияния — `unmarshal merged config: …`, ошибка построения — текст `box.New` без префикса (например `initialize outbound[0]: read certificate: …`). В `run` у той же ошибки есть префикс `create service: `.

Исходники: cmd/sing-box/cmd_check.go, box.go (`New`, `Close`).

### Что check проверяет

Всё, что делается в `box.New`:

- синтаксис и типы, неизвестные поля, известность каждого `type` (`unknown outbound type: …`); типы, которых нет в сборке, дают `… is not included in this build, rebuild with -tags with_…`;
- дубликаты тегов: inbounds; outbounds и endpoints (общее пространство имён); certificate providers; у `http_clients` — ещё и отсутствие `tag`;
- построение каждого inbound, outbound, endpoint, service, DNS-сервера и certificate provider, то есть разбор их опций. Здесь **читаются файлы**, на которые ссылается конфиг: сертификаты и ключи TLS, локальные rule-set (отсутствующий файл — ошибка);
- правила `route` и `dns` и определения rule-set (`router.Initialize`, `dnsRouter.Initialize`). Rule-set, на который ссылается DNS-правило, должен существовать;
- уровень лога, опции `experimental.debug`, создание Clash API и V2Ray API (без открытия порта);
- проверки устаревших возможностей: для тех, что удаляются в текущей или следующей минорной версии, без переменной `ENABLE_DEPRECATED_*` это FATAL (см. [ENABLE_DEPRECATED_*](#enable_deprecated_)). Сюда же относится отсутствие `route.default_domain_resolver` / `domain_resolver`, когда DNS-серверов больше одного, а адрес сервера — домен.

### Чего check не видит

Всё, что происходит в `Start` или позже. Такой конфиг проходит `check` с кодом 0, но не запускается или ломается в работе. Проверено или прочитано в коде 1.14.2:

| Проблема | Когда проявится |
|---|---|
| `detour` или член `selector`/`urltest`, указывающий на несуществующий тег; кольцо detour/групп | старт: `dependency[X] not found for outbound[Y]` / `circular outbound dependency` |
| `route.final` на несуществующий outbound | старт: `default outbound not found` |
| `dns.final` на несуществующий DNS-сервер | старт: `default DNS server not found` |
| `detour` DNS-сервера на несуществующий outbound или на «пустой» `direct` | старт |
| `rule_set` или `preferred_by` в правиле `route` с несуществующим тегом | старт: `initialize rule[N]: rule-set not found` / `outbound not found` (для `preferred_by`) |
| `download_detour` / `detour` в `http_client` у rule-set на несуществующий outbound, если нет кэшированной копии в `cache.db` и не удалось прочитать `initial_path`; отсутствующий тег `http_client` / `route.default_http_client` (независимо от кэша) | старт |
| занятый порт, запрет на прослушивание, `external_controller` Clash API, слушатель service `api` | старт |
| создание TUN (права администратора, wintun), `auto_route` | старт |
| недоступный путь `log.output`, `cache_file.path`; блокировка `cache.db` другим экземпляром (bbolt ждёт 1 с × 10 попыток) | старт (проверено: `check` эти файлы не создаёт) |
| загрузка удалённых rule-set, выпуск сертификатов ACME и провайдеров, NTP | старт и позже |
| действие правила `route` с `outbound`, которого нет | **ни `check`, ни старт**: ошибка `outbound not found` на каждом подпадающем соединении |
| `server` DNS-правила, которого нет | ни `check`, ни старт: при каждом запросе `transport not found`, правило пропускается |

Этот перечень и есть причина собственной проверки зависимостей в tray-sing-box (`internal/infrastructure/configfile/dependency.go`). Подробности по полям — в [route.md](route.md), [dns.md](dns.md), [outbounds.md](outbounds.md).

`check` можно запускать параллельно с работающим экземпляром: он не слушает порты, не создаёт TUN, не открывает `cache.db` и файл лога, ничего не скачивает (проверено).

Исходники: box.go, adapter/outbound/manager.go, dns/transport_manager.go, route/router.go, route/route.go, route/rule/rule_item_rule_set.go, route/rule/rule_item_preferred_by.go, dns/router.go, experimental/cachefile/cache.go.

## format

`sing-box format [-w]` переформатирует **каждый** файл конфига отдельно, без слияния и без `box.New`: ссылки между тегами не проверяются, но полный разбор (типы, неизвестные поля) выполняется.

| Флаг | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `-w`, `--write` | bool | `false` | записать результат обратно в исходный файл вместо stdout. Файл перезаписывается, только если текст изменился; путь записанного файла печатается в stderr. С `-c stdin` результат записывается в файл с именем `stdin` в рабочем каталоге (проверено) |

Без `-w` результат идёт в stdout. При нескольких файлах перед каждым печатается его абсолютный путь. Что меняется (проверено):

- ключи — в каноническом написании (`"Server"` становится `server`) и в порядке полей структур (`log`, `dns`, `ntp`, `certificate`, …, `inbounds`, `outbounds`, `route`, `services`, `experimental`);
- пустые массивы и объекты удаляются всегда; пустые скаляры (`false`, `0`, `""`) исчезают только у полей с `omitempty` — у большинства (`"sniff": false`, `"invert": false`), но не у всех: поля без него выводятся и пустыми, например `ntp` без сервера получает `"server": ""` и `"server_port": 0` (проверено);
- список из одного элемента в поле типа `string|[string]` сворачивается в строку (`["a.com"]` становится `"a.com"`);
- длительности нормализуются в запись Go: `"60s"` становится `"1m0s"`, `"90000ms"` — `"1m30s"`;
- висячие запятые исчезают, отступ — 2 пробела;
- комментарии (с 1.14.0) сохраняются, но могут переехать: комментарий перед ключом оказывается после значения предыдущего ключа.

Исходники: cmd/sing-box/cmd_format.go.

## merge

`sing-box merge <output-path>` сливает конфиги по [правилам выше](#слияние-нескольких-файлов) и пишет результат (отступ 2 пробела, права 0644) в `<output-path>`, печатая абсолютный путь в stderr. Флагов своих нет, входы задаются глобальными `-c` / `-C`.

- Перед записью содержимое файлов подставляется в конфиг: у inbound TLS — `certificate_path`, `key_path`, `ech.key_path`; у outbound TLS — `certificate_path`, `ech.config_path`; у SSH outbound — `private_key_path` (с `os.ExpandEnv`). Файл читается и разбивается на строки в массив (`certificate`, `key`, `private_key` …). **Поле `*_path` при этом остаётся** (проверено), но в рантайме встроенное значение имеет приоритет над путём. Нечитаемый файл молча пропускается.
- Результат проходит через разбор, но не через `box.New`: `merge` ссылки не проверяет. Это делает `check`.
- Комментарии при слиянии нескольких файлов теряются (для одного файла сохраняются).
- Выходной файл перезаписывается всегда: проверка «содержимое не изменилось» в 1.14.2 написана с инвертированным условием и не срабатывает.
- Недостающие родительские каталоги на Windows создаются, только если в пути разделители `\`. С `/` (`deep/x/out.json`) — ошибка `The system cannot find the path specified` (проверено).

Исходники: cmd/sing-box/cmd_merge.go.

## version

`sing-box version [-n]`:

| Флаг | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `-n`, `--name` | bool | `false` | вывести только номер версии (`1.14.2`) |

Без флага выводится `sing-box version 1.14.2`, пустая строка, затем `Environment: go1.26.8 windows/amd64`, `Tags: …` (теги сборки), `Revision: <commit>` и `CGO: enabled|disabled`. Всё — в stdout, код 0.

Исходники: cmd/sing-box/cmd_version.go, constant/version.go.

## generate

Генераторы, результат в stdout. Сеть и конфиг не нужны.

| Подкоманда | Аргументы и флаги | Вывод |
|---|---|---|
| `generate uuid` | — | UUID v4 |
| `generate rand <length>` | `--base64` (bool, `false`), `--hex` (bool, `false`) | `length` случайных байт: без флагов — сырые байты, иначе строка. Если заданы оба, побеждает `--base64` |
| `generate wg-keypair` | — | `PrivateKey: …` / `PublicKey: …` WireGuard (base64) |
| `generate reality-keypair` | — | `PrivateKey` / `PublicKey` для REALITY (X25519, base64url без паддинга) |
| `generate vapid-keypair` | — | `PrivateKey` / `PublicKey` VAPID (P-256, base64url) |
| `generate tls-keypair <server_name>` | `-m`, `--months` (int, `1`) — срок действия в месяцах | самоподписанный сертификат: сначала `PRIVATE KEY`, потом `CERTIFICATE` (PEM) |
| `generate ech-keypair <plain_server_name>` | — | PEM-блоки `ECH CONFIGS` и `ECH KEYS`. Флага `--pq-signature-schemes-enabled` из старого changelog больше нет |

Исходники: cmd/sing-box/cmd_generate.go, cmd/sing-box/cmd_generate_ech.go, cmd/sing-box/cmd_generate_tls.go, cmd/sing-box/cmd_generate_vapid.go, cmd/sing-box/cmd_generate_wireguard.go.

## rule-set

Работа с файлами rule-set: исходный формат JSON и бинарный `.srs`. Сами поля rule-set описаны в [route.md](route.md). Везде, где принимается путь к файлу, значение `stdin` означает стандартный ввод. Номера версий формата: 1–5, текущая — 5 (`C.RuleSetVersionCurrent`).

| Подкоманда | Аргументы | Флаги (тип, умолчание) | Что делает |
|---|---|---|---|
| `compile <source-path>` | 1 | `-o`, `--output` (string, `<file_name>.srs`) | JSON → `.srs`. По умолчанию имя: `x.json` → `x.srs`, иначе `x` → `x.srs`. Версия понижается до минимально достаточной: v5 → v4, если нет `package_name_regex`; v4 → v3, если нет `network_interface_address` / `default_interface_address`; v3 → v2, если нет `network_type` / `network_is_expensive` / `network_is_constrained` (проверено: v3 без таких полей сохраняется как v2) |
| `decompile <binary-path>` | 1 | `-o`, `--output` (string, `<file_name>.json`) | `.srs` → JSON. Отказывается, если внутри правила AdGuard (`unable to decompile binary AdGuard rules`). С 1.10.0 |
| `format <source-path>` | 1 | `-w`, `--write` (bool, `false`) | переформатировать JSON rule-set; с `-w` записать обратно (для `stdin` всегда stdout) |
| `upgrade <source-path>` | 1 | `-w`, `--write` (bool, `false`) | поднять версию 1 до текущей (5); для версии ≥ 2 печатает `already up-to-date` и ничего не меняет |
| `match <rule-set path> <IP address/domain>` | 2 | `-f`, `--format` (string, `source`) — `source` или `binary` | для каждого совпавшего правила печатает `match rules.[i]: …`. Вывод идёт в **stderr** (встроенный `println`); если совпадений нет — ничего, код 0. Автоопределение формата по расширению (`.json` / `.srs`) работает только при явном `-f ""`: с умолчанием `source` бинарный файл даёт ошибку разбора (проверено). IP-адреса поддерживаются с 1.10.0 |
| `merge <output-path>` | 1 | `-c`, `--config` (string, повторяемый); `-C`, `--config-directory` (string, повторяемый) | слить исходные JSON rule-set. Правила те же, что у конфигов: сортировка по пути, массивы `rules` конкатенируются; итоговая `version` — максимальная из входных. Здесь `-c` / `-C` — локальные флаги подкоманды, они перекрывают глобальные. С 1.11.0 |
| `convert <source-path>` | 1 | `-t`, `--type` (string, `""`; допустимо только `adguard`, без него ошибка `source type is required`); `-o`, `--output` (string, `<file_name>.srs`) | фильтр AdGuard DNS → `.srs` версии 2 (`x.txt` → `x.srs`). С 1.10.0 |

Исходники: cmd/sing-box/cmd_rule_set*.go, common/srs/, common/convertor/adguard/, constant/rule.go.

## geoip и geosite

Утилиты для старых баз. Сами поля `geoip` / `geosite` удалены из конфига в 1.12.0 (см. [deprecations.md](deprecations.md)), команды остались для перевода баз в rule-set. База открывается до выполнения любой подкоманды (кроме `--help`).

| Команда | Флаги (тип, умолчание) | Что делает |
|---|---|---|
| `geoip` (группа) | `-f`, `--file` (string, `geoip.db`) — persistent | открывает базу MaxMind типа `sing-geoip`, иначе ошибка `incorrect database type` |
| `geoip list` | — | коды стран из метаданных базы |
| `geoip lookup <address>` | — | код страны; `private` для непубличного адреса; `unknown`, если адреса нет в базе |
| `geoip export <country>` | `-o`, `--output` (string, подпись умолчания `geoip-<country>.srs`) | экспорт страны в **исходный JSON** rule-set версии 2 (`ip_cidr`). С умолчанием файл называется `geoip-<country>.json` (подпись флага вводит в заблуждение); `-o stdout` — в stdout |
| `geosite` (группа) | `-f`, `--file` (string, `geosite.db`) — persistent | открывает базу geosite |
| `geosite list` | — | категории с числом записей, по возрастанию |
| `geosite lookup [category] <domain>` | — | в каких категориях (или в указанной) есть домен |
| `geosite export <category>` | `-o`, `--output` (string, `geosite-<category>.json`) | экспорт категории в исходный JSON rule-set версии 2 (`domain`, `domain_suffix`, `domain_keyword`, `domain_regex`); `-o stdout` — в stdout |

Исходники: cmd/sing-box/cmd_geoip*.go, cmd/sing-box/cmd_geosite*.go, common/geosite/.

## tools

«Экспериментальные» утилиты, которые ходят в сеть через outbound из конфига. Конфиг читается как обычно, затем `box.New` и `PreStart`. Поднимаются логгер, кэш-файл, DNS, outbounds (вместе с ними стартуют и endpoints: менеджер исходящих запускает их в общем графе зависимостей), HTTP-клиенты, router и rule-set. Inbounds и services проходят только стадию инициализации и не слушают; внутренние службы (NTP, Clash API, V2Ray API) не стартуют. Если конфиг не задан и `config.json` нет, используется пустой конфиг: исходящий `direct` по умолчанию, локальный DNS. Явно указанный отсутствующий файл — ошибка (кроме буквального `-c config.json`: по коду он неотличим от умолчания и тоже заменяется пустым конфигом). Если в конфиге включён `cache_file`, а тот же `cache.db` держит работающий `run`, `tools` будет ждать блокировку около 10 с и завершится ошибкой.

| Команда | Аргументы | Флаги (тип, умолчание) | Что делает |
|---|---|---|---|
| `tools` (группа) | — | `-o`, `--outbound` (string, `""`) — persistent: тег outbound вместо outbound по умолчанию; несуществующий тег — `outbound not found` | |
| `tools connect <address>` | 1 | `-n`, `--network` (string, `tcp`; `tcp` или `udp`) | соединиться и связать stdin/stdout с соединением |
| `tools fetch <url>...` | ≥ 1 | — | GET и тело ответа в stdout. Схемы: без схемы → `http`, `http`, `https`, `http3` (QUIC, при `with_quic`). User-Agent `curl/7.88.0` |
| `tools synctime` | — | `-s`, `--server` (string, `time.apple.com`; порт по умолчанию 123); `-f`, `--format` (string, `2006-01-02 15:04:05 -0700`, раскладка Go); `-w`, `--write` (bool, `false`) — записать время в систему | запрос NTP и печать локального времени (без перевода строки). `-w` требует прав на смену времени (на Windows — администратор) |
| `tools networkquality` | — | `--config-url` (string, `""` — Apple `https://mensura.cdn-apple.com/api/v1/gm/config`); `--serial` (bool, `false`) — download и upload по очереди; `--max-runtime` (int, `20`, секунды); `--http3` (bool, `false`) | тест пропускной способности и отзывчивости (RPM), вывод в stderr. В changelog отдельно не отмечен, судя по коду — 1.14 |
| `tools stun` | — | `-s`, `--server` (string, `stun.voipgate.com:3478`) | внешний адрес и тип NAT по STUN, вывод в stderr. То же замечание о версии |

Исходники: cmd/sing-box/cmd_tools*.go, common/networkquality/, common/stun/, box.go (`PreStart`).

## api

С 1.14.0. `sing-box api <команда>` — клиент **gRPC-сервиса `api`** работающего экземпляра sing-box: того, что задаётся в `services` как `{"type": "api", …}` (listen-поля, `secret`, `tls`, `dashboard`, CORS; см. [experimental.md](experimental.md#service-api)). Это не Clash API и не V2Ray API. Сервис `api` — тот же интерфейс, через который графические клиенты и sing-box Dashboard управляют экземпляром (`StartedService` в daemon/started_service.proto). Без запущенного экземпляра с этим сервисом каждая команда завершается ошибкой `failed to connect to API service at …`.

### Подключение и авторизация

| Флаг | Тип | По умолчанию | Смысл и ограничения |
|---|---|---|---|
| `--url` | string | `$BOX_API_URL` | адрес сервиса. Без схемы подставляется `http://`. Допустимы `http` (gRPC поверх HTTP/2 без TLS) и `https` (TLS с проверкой по имени хоста); порт по умолчанию 80 / 443. Без URL — ошибка `missing API service URL, set --url or BOX_API_URL` |
| `--secret` | string | `$BOX_API_SECRET` | отправляется в заголовке `authorization: Bearer <secret>` |

У команды `api` отключён разбор флагов cobra: всё после `api` передаётся отдельному дереву команд. Глобальные `-c`, `-C`, `-D`, `--disable-color` в этом дереве неизвестны. По коду они не работают ни после `api`, ни до него (cobra пропускает их в аргументы `api`, и там они отвергаются как неизвестные). Конфиг для `api` и не нужен. Таблицы выводятся в stdout: в терминале — с выравниванием и заголовком в stderr, при перенаправлении — через табуляцию без заголовка. Коды gRPC переводятся в текст ошибки, `Unimplemented` дополняется версией API клиента.

### Подкоманды api

| Команда | Аргументы | Флаги (тип, умолчание) | Что делает |
|---|---|---|---|
| `api version` | — | — | версия sing-box на сервере; при расхождении версии API — предупреждение |
| `api status` | — | — | состояние, аптайм, память, горутины, соединения, трафик |
| `api logs` | — | `-f`, `--follow` (bool, `false`); `--level` (string, умолчание — уровень лога сервиса); `--search` (string, без учёта регистра) | журнал из буфера сервиса; `-f` — следить до Ctrl+C |
| `api outbounds` | — | — | outbounds: тег, тип, задержка последнего URL-теста |
| `api group list` / `show <group>` | 0 / 1 | — | группы outbounds и их состав |
| `api group select <group> <outbound>` | 2 | — | выбрать outbound в `selector` |
| `api group urltest <group>` | 1 | — | запустить URL-тест группы; результат появится позже (в справке упомянут несуществующий флаг `outbounds --group`) |
| `api mode` / `mode list` / `mode set <mode>` | 0 / 0 / 1 | — | текущий режим Clash, список режимов, смена режима (значение не проверяется, неизвестный режим «успешно» ставится) |
| `api connection list` | — | `--columns` (string-список, `id,network,destination,inbound,outbound,total`; доступны `id, network, source, destination, inbound, outbound, chain, rule, protocol, user, process, created, rate, total`) | открытые соединения |
| `api connection show <id>` | 1 | — | подробности соединения |
| `api connection close [<id>]` | 0–1 | `--all` (bool, `false`) | закрыть соединение по полному UUID или все; неизвестный id — тоже «успех» |
| `api networkquality` | — | `--config-url`, `--serial`, `--max-runtime` (`20`), `--http3` — как у `tools`; `-o`, `--outbound` (string, `""`) | тест выполняет **сервер** через свои outbounds |
| `api stun` | — | `--server` (string, `stun.voipgate.com:3478`); `-o`, `--outbound` (string, `""`) | STUN-тест на стороне сервера |
| `api openvpn status` / `auth` / `cancel` | — | у `auth` и `cancel`: `--endpoint` (string, `""` — единственный endpoint) | состояние endpoint OpenVPN, интерактивный ответ на запрос аутентификации, отмена запроса с остановкой клиента |
| `api openconnect status` / `auth` / `cancel` | — | у `auth`: `--endpoint`, `--callback-port` (uint16, `8020`) — локальный порт на `127.0.0.1` для SSO-колбэка браузера; у `cancel`: `--endpoint` | то же для OpenConnect. `auth` открывает браузер по умолчанию и **слушает** `127.0.0.1:<callback-port>` |
| `api tailscale status` | — | — | состояние endpoint Tailscale |
| `api tailscale peer list` / `peer show <peer>` | 0 / 1 | `--endpoint` (persistent у `peer`) | пиры |
| `api tailscale ping <peer>` | 1 | `--endpoint` | ping пира |
| `api tailscale exit-node` / `list` / `set <peer>` / `clear` | 0 / 0 / 1 / 0 | `--endpoint` (persistent у `exit-node`) | текущий exit node, кандидаты, выбор, сброс |
| `api tailscale logout` | — | `--endpoint` | выйти из сети Tailscale |
| `api tailscale certificate list` / `export <domain>` | 0 / 1 | `--endpoint` (persistent); у `export`: `--cert-file` (string, `<domain>.crt`, `-` = stdout), `--key-file` (string, `<domain>.key`, `-` = stdout), `--min-validity` (duration, `0`) — обновить, если истекает раньше | HTTPS-сертификаты Tailscale |
| `api tailscale ssh [user@]<peer>` | 1 | `--endpoint` | запускает **локальный** `ssh` из `PATH` на адрес пира. Трафик должен идти в tailnet через этот sing-box (обычно TUN); пользователь по умолчанию — текущий (домен Windows отбрасывается); код выхода ssh пробрасывается |
| `api tailscale taildrop targets` / `list` / `send <peer> <file>...` / `get <name> [output]` / `delete <name>...` | 0 / 0 / ≥ 2 / 1–2 / ≥ 1 | `--endpoint` (persistent у `taildrop`) | Taildrop: получатели, входящие файлы, отправка, сохранение, удаление |
| `api usbip status` | — | `--service` (string, `""` — все) | какие USB-устройства раздаются |
| `api usbip device list` / `device show <device>` | 0 / 1 | — | локальные USB-устройства (bus id, `vid:pid` или `vid:pid:serial`) |
| `api usbip share <device>...` | любое | `--service` (string, `""` — единственный `usbip-server` с `provider: dynamic`); `--all` (bool, `false`); `--capture` (bool, `false`) — отвязать устройство от драйвера, нужны права root / администратора | раздавать локальные устройства, пока команда не прервана. Требует сборки с `with_usbip` (Linux, Windows, macOS с CGO), иначе ошибка |

Прерывание интерактивных `openvpn auth`, `openconnect auth`, `usbip share` завершает процесс с кодом 130.

Исходники: cmd/sing-box/cmd_api*.go, daemon/client.go, daemon/started_service.proto, service/api/server.go, option/api.go.

## completion и help

- `sing-box completion bash|fish|powershell|zsh [--no-descriptions]` — скрипт автодополнения от cobra; `--no-descriptions` (bool, `false`) убирает описания. Для PowerShell: `sing-box completion powershell | Out-String | Invoke-Expression`.
- `sing-box help [команда]` и `-h` / `--help` у любой команды.
- Скрытые команды cobra `__complete` / `__completeNoDesc` обслуживают автодополнение.
- Файлы в `release/completions/` собираются отдельной программой (теги сборки `generate,generate_completions`) и в `sing-box.exe` не входят.

Исходники: cmd/sing-box/generate_completions.go; cobra.

## Скрытые и служебные команды

| Команда | Что делает |
|---|---|
| `netns-holder` | скрыта; читает stdin до EOF и выходит с кодом 0. `box.New` запускает её как `/proc/self/exe netns-holder`, чтобы удерживать сетевые пространства имён на Linux. На Windows бесполезна |

Отдельный бинарник `boxdd` (служба sing-box for Desktop, experimental/boxdd) в `sing-box.exe` не входит, его флаги и переменные (`INVOCATION_ID` и др.) сюда не относятся.

Исходники: cmd/sing-box/cmd_netns_holder.go, common/netns/netns.go.

## Коды завершения

| Код | Когда |
|---|---|
| 0 | успех; `run`, остановленный Ctrl+C / `SIGTERM` (даже если при закрытии были ошибки); `sing-box` без аргументов; `rule-set match` без совпадений; `rule-set upgrade` на актуальной версии |
| 1 | любая ошибка, выведенная как `FATAL` (`log.Fatal` вызывает `os.Exit(1)`): ошибки cobra (неизвестная команда или флаг, неверное число аргументов), чтение, разбор и слияние конфига, `create service`, `start service`, неудачная перезагрузка по `SIGHUP`, зависание остановки дольше 10 с, устаревшая возможность без `ENABLE_DEPRECATED_*` |
| 2 | паника Go (стандартный код рантайма) |
| 130 | прерванные интерактивные `api openvpn auth`, `api openconnect auth`, `api usbip share` |
| код `ssh` | `api tailscale ssh` возвращает код клиента ssh |
| код дочернего процесса | `run` на Linux, перезапущенный в user namespace |

Процесс, убитый извне (`TerminateProcess`, `SIGKILL`), своего кода не выбирает.

Исходники: cmd/sing-box/main.go, log/observable.go (`output`), cmd/sing-box/cmd_run.go, cmd/sing-box/cmd_api_openvpn_auth.go, cmd/sing-box/cmd_api_openconnect_auth.go, cmd/sing-box/cmd_api_usbip_share.go, cmd/sing-box/cmd_api_tailscale_ssh_windows.go, cmd/sing-box/cmd_run_userns_linux.go.

## Переменные окружения

Перечень составлен поиском `os.Getenv` / `os.LookupEnv` / `os.Environ` / `os.ExpandEnv` по дереву sing-box 1.14.2, без тестов, `cmd/internal` и `experimental/boxdd`. Переменные библиотек-зависимостей (sing, форк quic-go, tailscale, cronet-go) здесь не собраны.

### ENABLE_DEPRECATED_*

Когда конфиг использует устаревшую возможность, менеджер устаревания (подключается в `preRun` для всех команд, срабатывает при `box.New`, то есть в `run`, `check`, `tools`) поступает так:

- удаление запланировано больше чем через одну минорную версию — строка `WARN` и работа продолжается;
- удаление запланировано в текущей или следующей минорной версии — `ERROR` с описанием и `FATAL to continuing using this feature, set environment variable ENABLE_DEPRECATED_<NAME>=true`, код 1. Если переменная `ENABLE_DEPRECATED_<NAME>` — истина по `strconv.ParseBool` (`1`, `t`, `T`, `true`, `TRUE`, `True`; `yes` — нет, проверено), вместо этого только `WARN`.

В 1.14.2:

| Переменная | Возможность | Устарела / удаление | Поведение в 1.14.2 без переменной |
|---|---|---|---|
| `ENABLE_DEPRECATED_OUTBOUND_DNS_RULE_ITEM` | пункт `outbound` в DNS-правилах | 1.12.0 / 1.14.0 | FATAL (проверено) |
| `ENABLE_DEPRECATED_MISSING_DOMAIN_RESOLVER` | нет `route.default_domain_resolver` и `domain_resolver` в dial-полях при адресе-домене и более чем одном DNS-сервере | 1.12.0 / 1.14.0 | FATAL (проверено; `check` тоже падает) |
| `ENABLE_DEPRECATED_LEGACY_DOMAIN_STRATEGY_OPTIONS` | `domain_strategy` в dial-полях (сообщается, когда адрес доменный и резолвится локально, `domain_strategy` не `as_is`, а `domain_resolver.strategy` не задан) | 1.12.0 / 1.14.0 | FATAL (проверено; `check` тоже падает) |
| `ENABLE_DEPRECATED_INLINE_ACME_OPTIONS` | встроенные опции ACME в TLS | 1.14.0 / 1.16.0 | WARN |
| `ENABLE_DEPRECATED_LEGACY_RULE_SET_DOWNLOAD_DETOUR` | `download_detour` удалённого rule-set | 1.14.0 / 1.16.0 | WARN |
| `ENABLE_DEPRECATED_DNS_RULE_RULE_SET_IP_CIDR_ACCEPT_EMPTY` | `rule_set_ip_cidr_accept_empty` в DNS-правилах | 1.14.0 / 1.16.0 | WARN |
| `ENABLE_DEPRECATED_LEGACY_DNS_ADDRESS_FILTER` | адресные поля DNS-правил без `match_response` | 1.14.0 / 1.16.0 | WARN |
| `ENABLE_DEPRECATED_LEGACY_DNS_RULE_STRATEGY` | `strategy` в действии DNS-правила | 1.14.0 / 1.16.0 | WARN |
| `ENABLE_DEPRECATED_INDEPENDENT_DNS_CACHE` | `dns.independent_cache` | 1.14.0 / 1.16.0 | WARN (проверено) |
| `ENABLE_DEPRECATED_STORE_RDRC` | `cache_file.store_rdrc` | 1.14.0 / 1.16.0 | WARN |
| `ENABLE_DEPRECATED_IMPLICIT_DEFAULT_HTTP_CLIENT` | неявный HTTP-клиент по умолчанию для удалённых rule-set | 1.14.0 / 1.16.0 | WARN |

Часть «новых» устаревших возможностей в сочетании с новыми полями 1.14 — жёсткая ошибка независимо от переменной (например, `rule_set_ip_cidr_accept_empty` или адресные фильтры вне legacy-режима DNS). Подробнее — [deprecations.md](deprecations.md). В документации sing-box эти переменные не описаны вовсе.

Исходники: experimental/deprecated/stderr.go, experimental/deprecated/constants.go, cmd/sing-box/cmd.go, common/dialer/dialer.go, route/rule/rule_item_outbound.go, route/rule/rule_dns.go, dns/router.go.

### Остальные переменные

| Переменная | Кто читает | Смысл |
|---|---|---|
| `BOX_API_URL`, `BOX_API_SECRET` | `api` | адрес и секрет сервиса, если не заданы `--url` / `--secret` |
| `SUDO_USER`, `SUDO_UID`, `SUDO_GID` | `preRun` всех команд; системный прокси Linux; ccm/ocm | Unix: файлы, которые создаёт sing-box (лог, кэш и т. п.), передаются во владение пользователю, запустившему `sudo`. На Windows практического эффекта нет |
| `HOME`; через `os.UserConfigDir` / `os.UserCacheDir` — `APPDATA`, `LOCALAPPDATA` (Windows), `XDG_CONFIG_HOME`, `XDG_CACHE_HOME` (Unix) | constant/path.go | каталоги поиска ресурсов `FindPath`; в 1.14.2 используется только на Android (`rish`) |
| `LOCALAPPDATA` (через `os.UserCacheDir`) | common/windivert (Windows) | кэш драйвера WinDivert: `%LOCALAPPDATA%\sing-box\windivert\v<версия>\`. Нужен `bridge` outbound и TLS spoof на Windows; без переменной они не запустятся |
| `DISABLE_NFTABLES` | tun inbound (Linux, `auto_redirect`) | истина — использовать iptables вместо nftables |
| `SINGBOX_TS_TUN_DEBUG` | Tailscale (Unix) | отладка TUN-устройства Tailscale |
| `DNSSD_UDS_PATH` | локальный DNS (macOS) | путь к сокету mDNSResponder |
| `CLAUDE_CONFIG_DIR` | service `ccm` | где искать учётные данные |
| `CODEX_HOME` | service `ocm` | где искать учётные данные |
| `SystemRoot`, `TEMP` / `TMP` / `USERPROFILE` (через `os.TempDir`) | сервер Tailscale SSH (Windows) | путь к `cmd.exe`, окружение сеанса, временный каталог |
| `PATH` | `api tailscale ssh`; загрузка `libcronet.dll` (naive outbound, `with_purego`) | поиск `ssh`. `libcronet.dll` ищется в каталоге exe, затем по `PATH` (наблюдение проекта tray-sing-box; код загрузчика — в библиотеке cronet-go, не в этом дереве) |
| любые (`$VAR` в путях) | `os.ExpandEnv` | см. [Рабочий каталог и относительные пути](#рабочий-каталог-и-относительные-пути) |
| `GODEBUG`, `GOMAXPROCS`, `GOGC`, `GOMEMLIMIT`, `GOTRACEBACK` | рантайм Go | стандартные настройки рантайма; `experimental.debug` может переопределить GC и лимит памяти |

Переменные прокси (`HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY`) sing-box не использует: вызовов `ProxyFromEnvironment` в дереве нет. Единственное исключение — запасная ветка `common/networkquality` с `http.DefaultTransport`, недостижимая из CLI. Язык сообщений в CLI от окружения не зависит: локаль задают только графические клиенты.

Исходники: cmd/sing-box/cmd.go, cmd/sing-box/cmd_api.go, constant/path.go, constant/path_unix.go, common/windivert/driver_asset_windows.go, protocol/tun/inbound.go, protocol/tailscale/tun_device_unix.go, dns/transport/local/local_darwin.go, service/ccm/credential.go, service/ocm/credential.go, protocol/tailscale/tailssh/server_helper_windows.go, protocol/tailscale/tailssh/user_windows.go, cmd/sing-box/cmd_api_tailscale_ssh.go, common/settings/proxy_linux.go.

## Особенности Windows

- Нет `SIGHUP`, а значит, нет перезагрузки конфига на лету: только перезапуск процесса. Корректная остановка — Ctrl+C / Ctrl+Break в своей консоли. `TerminateProcess` обходит `Close`.
- ANSI-цвета пишутся и в перенаправленный stderr (файл, канал). Убрать их можно только `--disable-color`.
- UTF-8 с BOM не читается: в старом Блокноте сохраняйте как «UTF-8» без BOM.
- `-C` берёт только файлы с суффиксом `.json` в нижнем регистре.
- `os.ExpandEnv` в путях понимает `$VAR` / `${VAR}`, но не `%VAR%`.
- `merge` создаёт недостающие каталоги вывода, только если путь записан через `\`.
- Только для Linux: перезапуск в user namespace, `netns-holder`, `network_namespaces`, `DISABLE_NFTABLES`, смысл `SUDO_*`. TUN, `auto_route`, `auto_redirect`, redirect/tproxy и правила по процессам описаны в [inbounds.md](inbounds.md) и [route.md](route.md).
- `tools synctime -w` и `api usbip share --capture` требуют прав администратора. `api openconnect auth` открывает браузер и слушает `127.0.0.1:8020`.
- Драйвер WinDivert (`bridge` outbound, TLS spoof) кэшируется в `%LOCALAPPDATA%`.
- Для автодополнения есть `completion powershell`.

## Как это использует tray-sing-box

- **Запуск VPN**: `sing-box.exe run -c <data>\config.json` (абсолютный путь), рабочий каталог задаётся не через `-D`, а через `cmd.Dir` = каталог данных. Поэтому `cache.db`, локальные rule-set, относительный `log.output` лежат в каталоге данных. stdout и stderr идут напрямую в `sing-box-console.log` (дескриптор с дописыванием). Там оказываются и ошибки CLI (`FATAL decode config …`, `create service`, `start service`), которые никогда не попадают в `log.output`. Флаг `--disable-color` не передаётся, поэтому в этом файле есть ANSI-коды, и приложение вычищает их при показе. Добавить `--disable-color` к `run` и `check` было бы равнозначно и проще.
- **Остановка и применение настроек**: процесс завершается по PID через `TerminateProcess` (корректного `Close` нет). Любое изменение конфига применяется перезапуском (`RestartIfRunning`): на Windows другого пути нет.
- **Проверка перед каждым сохранением**: копия конфига пишется в `<data>\.singbox-check-*.json`, затем `sing-box.exe check -c <копия>` со скрытым окном, тем же окружением и `cmd.Dir` = каталог данных, чтобы относительные пути разрешались так же, как у `run`. `check` не конфликтует с работающим VPN: не слушает, не трогает `cache.db` и лог. Часть того, что `check` пропускает (таблица [Чего check не видит](#чего-check-не-видит)), закрывает собственная проверка `internal/infrastructure/configfile/dependency.go`: зависимости и кольца исходящих, `route.final`, ссылки правил на rule-set и `preferred_by`, `download_detour`/`http_client` rule-set, `route.default_http_client`, `detour` DNS-серверов и NTP. Не закрыты: `dns.final`, `detour` на «пустой» `direct`, `domain_resolver` DNS-серверов, порты, TUN, сеть — перечень в [config.md](config.md#заметки-для-tray-sing-box).
- **Версия для обновлений**: `sing-box.exe version`, из вывода разбирается первая строка `sing-box version X` (у установленного бинарника и у скачанного — тот должен сообщить ожидаемую версию). Альтернатива — `version -n`, она печатает только номер.
- **Проверка конфига новой версией** (`updater.CheckConfig`): перед заменой скачанный `sing-box.exe` из `Bin\.sing-box-update-*` запускается как `check -c <data>\config.json` с тем же окружением и рабочим каталогом, что у VPN. Проверяются обе версии: если новая конфиг отвергает, а установленная принимает, обновление отменяется с текстом sing-box; если отвергают обе, обновление идёт только при остановленном VPN. Если не стартует уже установленная новая версия, возвращается прежняя (`.old`) — но только когда прежняя принимает конфиг (`UpdateService.checkConfig`, `notStartedError`).
- **Окружение** (`process.SingBoxEnv`) не наследуется, а собирается заново: `SystemRoot`, `windir`, `SystemDrive`, `ProgramData`, `ProgramFiles`, `PATH = <Bin>;System32;Windows;System32\Wbem`, `TEMP` = `TMP` = `<data>\tmp`, `USERPROFILE = <data>`. Из окружения пользователя пропускаются только `ENABLE_DEPRECATED_*`, нормализованные через `ParseBool`: sing-box читает их так же. Следствия по таблице выше: `BOX_API_*`, `GODEBUG` и прочие настройки пользователя до sing-box не доходят; `$VAR` в путях конфига раскрываются только из этого набора; `APPDATA` и `LOCALAPPDATA` не заданы, поэтому возможности на WinDivert (`bridge` outbound, TLS spoof) под приложением не запустятся: драйвер кладётся в `os.UserCacheDir()`, а без `LOCALAPPDATA` это ошибка `windivert: locate user cache dir` (по коду common/windivert). Исходящий `bridge` guard приложения и так не пропускает (его нет в `allowedOutboundTypes`), а `tls.spoof` и `tls_spoof` в `route-options` пропускает — такой конфиг пройдёт check и будет ломать соединения.
- **Синтаксис**: sing-box принимает комментарии и висячие запятые, а редактор приложения читает `config.json` строгим `encoding/json`. Конфиг с комментариями, написанный вручную, sing-box запустит, но приложение не сможет его редактировать (первый конфиг через страницу настроек прямо требует JSON без комментариев).
- Приложение не пользуется `merge`, `-C`, `format`, `api` и `tools`. Сервис `api` в его конфиге невозможен: guard не пропускает раздел `services`.

Исходники (tray-sing-box): internal/infrastructure/process/manager.go, internal/infrastructure/process/env_windows.go, internal/infrastructure/singboxcheck/checker.go, internal/infrastructure/updater/updater.go, internal/domain/update_service.go, internal/infrastructure/configfile/editor.go, internal/infrastructure/configfile/dependency.go.

## Расхождения документации и кода

- docs/configuration/index.md для `format` и `merge` приводит пример с `-D config_directory`. `-D` — рабочий каталог, каталог конфигов задаётся `-C`.
- ENABLE_DEPRECATED_* нигде в документации не описаны. deprecated.md не упоминает «отсутствующий domain resolver» и `domain_strategy` в dial-полях как запланированные к удалению в 1.14.0, хотя код 1.14.2 пишет «will be removed in sing-box 1.14.0» и без переменной завершается с FATAL.
- Документация по `log` не называет уровень по умолчанию; в коде это `trace`.
- Changelog (1.5.0) пишет, что `merge` «заменяет» пути встроенным содержимым. На деле встроенное значение добавляется, а поле `*_path` остаётся.
- Внутренние несоответствия кода: у `geoip export` подпись умолчания `geoip-<country>.srs`, а пишется `geoip-<country>.json` (JSON); у `rule-set match` автоопределение формата недостижимо при умолчании `-f source`; справка `api group urltest` ссылается на несуществующий флаг `outbounds --group`; проверка «не перезаписывать неизменённый файл» в `merge` и `rule-set merge` инвертирована.
- Версии появления `tools networkquality`, `tools stun`, `generate vapid-keypair`, `rule-set upgrade` в changelog не указаны.
