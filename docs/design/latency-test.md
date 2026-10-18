# Тест задержки серверов и «выбрать самый быстрый» — проект

Статус: проект, к реализации по шагам 0–2 (§3.12). Пункты TODO «Интеграция с Clash API» и «Тест задержки серверов».


Проект собран судьёй из трёх независимых вариантов (minimal, rich, secure) в октябре 2026 года. Код читался на ветке с поддержкой Clash/Xray, исходники sing-box — v1.14.2 (`af6e64c`), Windows-файлы sing-tun — ревизии `ddaa4ca` из `go.mod` sing-box. Ничего не запускалось.

---

## 1. Оценки (1–10)

| Критерий | minimal (отдельный краткоживущий sing-box) | rich (оверлей `-c` с первого шага, все функции) | secure (оверлей `-c`, узкие типизированные операции) |
|---|---|---|---|
| Безопасность запуска VPN | **10**. `Manager.Start` не меняется. Если тест не удался, сломался только тест | **4**. Меняется каждый запуск: цикл из 3 попыток в `Start`. Порт слушается на стадии Started, то есть после TUN (проверено, `box.go start()`), поэтому каждая неудачная попытка = подъём и снятие TUN. Отказ после grace 1,5 с уходит в монитор с backoff. Режим «перекрыть порт пользователя» | **6**. Политика осторожная: нет оверлея при своём `clash_api`, `clash_mode` или нестрогом JSON. Порт проверяется пробной привязкой, есть запуск без оверлея. Но `Start` по-прежнему меняется на каждом запуске, а поздний отказ сжигает до 2 попыток монитора |
| Безопасность и приватность | **9**. Секрет передаётся через stdin: его нет ни на диске, ни в командной строке. Владелец соединения проверяется по PID. `config.json` и guard не трогаются. Job-объект. Остаток — окно между `Start` и `AssignProcessToJobObject` (закрывается, см. §3.2) | **7**. Проверка PID, секрет в админском файле, `authPassive`. Но владелец сессии видит соединения с путями программ. Приложение работает поверх чужого `clash_api` без секрета. Флажок, включающий API со страницы | **9**. Секрета нет на странице, только типизированные операции, проверка собеседника на каждом соединении, файл только для администраторов. Новые раскрытия данных включаются только из трея. Ужесточение guard |
| Ценность для пользователя | **6**. Задержка и «самый быстрый». Трафик, соединения и selector без рестарта отложены | **10**. Все пункты TODO | **8**. Задержка, «самый быстрый», скорость, позже selector без рестарта |
| Размер и риск реализации (10 = мало и безопасно) | **8**. Средний объём, всё ново и изолировано | **2**. Огромный. Меняются семантика `ActiveOutbound` (от неё зависит `DPIBypassService.EnableChain`) и `SwitchOutbound`. Появляется исключение «сохранение без истории». Алиасы, сверка, нейтральный режим | **5**. Оверлей плюс поэтапное наращивание |
| Тестируемость | **8**. `probePlan` — чистая функция, Clash API на httptest, поддельный sing-box. Но реальный тест упорядочивания задержек офлайн невозможен (§2, R1) | **6**. Много тестов, но интеграционный тест с CA из секции `certificate` не сработает (R1) | **7**. То же замечание (R1) |
| Совместимость с существующим кодом | **9**. `SwitchOutbound`/`UseOutbound`, `HelperOutput`-реестр, `indexedEntry`, `redactSecrets`, `relayTags`, `localServer` — всё уже есть | **4**. Ломает допущение `SyncOutbounds` («теги в рантайме не адресуются»), правило «каждое сохранение архивируется», `ActiveOutbound` | **7** |
| **Сумма из 60** | **50** | **33** | **42** |

**Основа для синтеза — minimal.** Из secure берутся: порядок работы с «самым быстрым» (запас и отказ при раздельной маршрутизации), `opMu` только на шаг переключения, ужесточение guard, правила для живого API на будущее. Из rich — оговорка про `ActiveOutbound` групп, предупреждение о DPI-цепочке и `authPassive` для будущих опросов.

---

## 2. Проверенные и опровергнутые утверждения

### Подтверждено чтением кода в этой сессии

| # | Утверждение | Источник |
|---|---|---|
| C1 | Файлы `-c` сортируются по строке пути. Каждый файл сначала разбирается **отдельно**, как полный `Options` (`DisallowUnknownFields`). Затем `MergeJSON(source=очередной, destination=уже слитое)`: у скаляров побеждает **более ранний** файл, массивы склеиваются (ранний первым). Ошибка `cannot merge json object into …` возникает, только когда в раннем файле объект, а в позднем не объект: `config.json` с `"experimental": null` за оверлеем | `cmd/sing-box/cmd_run.go:97-129`, `sing/common/json/badjson/merge.go` |
| C2 | Ключи в другом регистре (`Clash_API` и `clash_api`) остаются в слитом JSON двумя ключами. Последующий разбор без учёта регистра декодирует их в один указатель поле за полем, и **позже в тексте** — значит, побеждает. При оверлее, который сортируется раньше, это поля пользователя. Это подтверждает довод secure, F | badjson `object.go` (`Put` по точному ключу) + разбор `encoding/json` |
| C3 | `-c stdin` = `io.ReadAll(os.Stdin)` | `cmd_run.go:readConfigAt` |
| C4 | Clash API слушает на `StartStateStarted` внутренних служб, то есть после старта inbound (TUN). Ошибка = `external controller listen error`, и падает весь старт | `box.go start()`, `clashapi/server.go Start` |
| C5 | Авторизация: `Bearer` или `?token=` у WebSocket. Сравнение не по постоянному времени. `Host` не проверяется. CORS по умолчанию `*`. Без `external_ui` `POST /upgrade/ui` отвечает 404. `PUT /configs` — пустая операция | `clashapi/server.go`, `api_meta_upgrade.go`, `configs.go` |
| C6 | `getProxyDelay`: `timeout` — int16 мс. URL `http://…` заменяется на gstatic. Контекст `context.Background()`+тайм-аут. Ответы 504/503, `delay==0` → 503. При ошибке удаляется история тега. **После каждого теста вызывается `PerformUpdateCheck` у всех `urltest`, куда входит тег** | `clashapi/proxies.go:211-268` |
| C7 | `performUpdateCheck` при смене выбора вызывает `interruptGroup.Interrupt(...)`. Значит, «Проверить задержку» на **живом** экземпляре может переключить `urltest` пользователя и оборвать соединения: внутренние всегда, внешние при `interrupt_exist_connections`. Сильный довод против замера на процессе VPN | `protocol/group/urltest.go:488-507` |
| C8 | `Selector.Start`: выбор из `cache_file` (если он среди участников) важнее `default`. `SelectOutbound` пишет его в `cache.db` | `protocol/group/selector.go` |
| C9 | Менеджер режима Clash создаётся при наличии объекта `clash_api` или службы `api`, по умолчанию режим `Rule`. Без менеджера `clash_mode` не срабатывает никогда. Режим из `cache_file` загружается | `box.go:247-258`, `clashmode/manager.go`, `rule_item_clash_mode.go` |
| C10 | При непустом `external_controller` логгер форматирует **каждое** сообщение независимо от `log.level` | `box.go:181`, `log/observable.go:179-197` |
| C11 | Без `with_clash_api` — `clash api is not included in this build…`. Официальная Windows-сборка этот тег включает | `include/clashapi_stub.go`, `release/DEFAULT_BUILD_TAGS_WINDOWS` |
| C12 | `sing-box check` идёт через тот же `readConfigAndMerge` и `box.New`. Значит, `check -c config.json -c overlay` проверяет слияние и создание clash-сервера, но не `listen` | `cmd_check.go:29-35` |
| C13 | Конкурентность групповых тестов sing-box — 10 | `protocol/group/urltest.go:401` |
| C14 | Монитор интерфейса по умолчанию в sing-tun на Windows берёт только маршруты `/0`, пропускает `IfTypePropVirtual` и loopback и **не учитывает интерфейсы своего процесса** (`RegisterMyInterface` в `checkUpdate` не читается). То, что удерживает монитор самого VPN от своего TUN, удерживает и второй процесс | sing-tun `monitor_windows.go:60-115`, `monitor_shared.go:147` |
| C15 | `strict_route`: «permit» по AppID exe (вес 13), «block ipv6» (12), «block dns :53» (10). Блок IPv4 **закомментирован**. Тестовый экземпляр должен быть **тем же** `<Bin>\sing-box.exe`: у копии был бы другой AppID и закрытый DNS:53/IPv6 мимо TUN | sing-tun `tun_windows.go:169-361` |
| C16 | `auto_detect_interface`: адрес из префикса локального интерфейса (127.0.0.1) привязывается к нему (`ByAddr`), остальное — к интерфейсу по умолчанию. `default_interface` важнее | `common/dialer/default.go:99-130`, `route/network.go:378-404` |
| C17 | `RootPoolFromContext(ctx)` при пустом контексте возвращает `nil` (системные корни) | `adapter/certificate.go:16-22` |
| C18 | Приложение запускает `exec.Command(singBox,"run","-c",configPath)`, `Dir=data`, `Env=SingBoxEnv`, `StartGraceMs=1500`, и подхватывает любой повышенный экземпляр того же пути | `process/manager.go:75-245`, `config.go:40` |
| C19 | `HelperOutput` ждёт без тайм-аута. Регистрация под `helperMu`, `findProcesses` держит его до снимка | `process/windows.go:171-194, 234-237` |
| C20 | `hideConsoleWindow` задаёт `CreationFlags` (`CREATE_NO_WINDOW|DETACHED_PROCESS`), к ним можно добавить `CREATE_SUSPENDED` | `process/windows.go:467-480` |
| C21 | Guard пропускает новый loopback `clash_api.external_controller` **без** `secret`. `secret` нет в `secretKeys` | `configfile/guard.go:247-252`, `secrets.go:47-52` |
| C22 | `SwitchOutbound` перенаправляет **все** ссылки на прокси, а если таких нет, ставит `route.final=tag` (маршрут через группу заменяется узлом). Сохраняет **всегда**: `save` → `.bak` + архив. `ActiveOutbound` для маршрута через группу даёт `""`. `UseOutbound` = `Switch` + `RestartIfRunning` | `configfile/editor.go:895-1001, 102-150`, `domain/settings_service.go:95-107` |
| C23 | `SyncOutbounds`: если изменились только имена, `NeedsRestart=false` («the app never addresses an outbound by tag at runtime»). С живым API теги в работающем sing-box расходятся с конфигом. Для отдельного экземпляра это неважно | `editor.go:768-771`, `subscription_service.go:52-54` |
| C24 | Слияние переименовывает и удаляет `default` у selector | `merge.go:280, 482` |
| C25 | Id пунктов трея: toggle 3, импорт 5, QR 6, настройки 8, sing-box 9, выход 15. Тест в песочнице использует их | `ui/tray.go:86-112`, `lifecycle-test.ps1:329-334` |
| C26 | `handleSwitch` берёт `opMu`, `handleVPN` — нет. `fail()` = 400. CSP `connect-src 'self'` | `webui/server.go:48, 563-601` |
| C27 | `indexedEntry` (`outbound[N]` в ошибке sing-box) уже есть. `box.New` пишет `initialize outbound[N]` | `configfile/refusal.go:343`, `box.go:374` |
| C28 | Go на Windows не ставит слушателям `SO_REUSEADDR`, но и `SO_EXCLUSIVEADDRUSE` не ставит. В `x/sys` v0.38.0 нет `GetExtendedTcpTable` | GOROOT `net/sockopt_windows.go:26-32`; `zsyscall_windows.go` |
| C29 | `SetTooltip` копирует строку в `[128]uint16` без гарантии NUL (rich, F18) | `third_party/systray/systray_windows.go:290-302` |
| C30 | Правила `domain_resolver` (справочник): при одном DNS-сервере берётся сервер по умолчанию, при двух и более без резолвера — устаревшая логика через DNS-правила | `docs/sing-box/shared.md:78-86` |

### Опровергнуто или уточнено

- **R1 (rich §9.4, secure §8) — опровергнуто.** Интеграционный тест «секция `certificate` с тестовым CA + свой https-URL замера» не сработает. Delay-тест Clash API идёт с `context.Background()`, а `RootPoolFromContext` даёт `nil`, то есть системные корни (C6, C17). Секция `certificate` действует на TLS **узлов**, но не на запрос к URL теста. Офлайн с настоящим sing-box можно проверить только классификацию (тайм-аут или ошибка), адресацию тегов, готовность и жизненный цикл. Порядок задержек проверяется через сеть (gstatic): тест в обычном режиме или сетевой этап песочницы.
- **R2 (rich §2 «C: трафик уйдёт в туннель», secure §2 «нельзя полагаться…») — сильно ослаблено.** На Windows `checkUpdate` не делает различий по процессу (C14). Если бы TUN попадал в выбор «интерфейса по умолчанию», зациклился бы сам VPN. Второй процесс видит ту же таблицу маршрутов и делает тот же выбор. Его сокеты привязываются к физической карте тем же `IP_UNICAST_IF`, которым основной VPN звонит своим серверам (C16). `strict_route` его пропускает: тот же exe — тот же AppID (C15). Проверить в песочнице всё равно нужно, но это подтверждение, а не основа дизайна.
- **R3 (secure: в C «учётные данные ещё в одном процессе и файле») — уточнено.** Со stdin файла нет. Процесс повышенный: процесс среднего уровня не прочитает его память, потому что у объекта процесса по умолчанию стоит NO_READ_UP. Поэтому тестовый экземпляр **обязан** быть повышенным. Облегчённый вариант «запустить его без повышения» отвергнут: в установленной раскладке он раскрыл бы учётные данные из `config.json`, закрытого для не-администраторов.
- **R4 (rich, C: «bbolt-блокировка `cache.db` ~10 с», «качаются удалённые rule-set») — неверно для C в варианте minimal.** `cache_file` и `rule_set` не копируются.
- **R5 (все три) — пропущено.** Слитый конфиг проходит через `badjson.Decode`, который читает токенами без `UseNumber`, так что числа становятся float64. Повторяющиеся ключи в одном файле при `Put` заменяются целиком, а одиночный разбор сливал их поле за полем. На практике целые не больше 2^53 точны, а конфиги, записанные редактором приложения, повторов не содержат. Но оверлей меняет разбор **каждого** конфига при **каждом** запуске. Это довод держать оверлей выключенным по умолчанию и прогонять `check` заранее (C12).
- **R6 (rich F3, «объект поверх не-объекта даёт ошибку») — уточнено.** Ошибка возникает, только если в более раннем файле объект (C1). Таблица rich случай `experimental: null` всё равно обрабатывает верно.
- **R7 (minimal: `opMu` на всю проверку ради замены `sing-box.exe`) — не нужно.** Проверка только читает (снимок конфига в памяти). Переименовать работающий exe Windows разрешает, а `Manager.Stop` помощника не трогает (C19). Держать `opMu` до 30 с значит блокировать трей, импорт, «Выход» и `--quit` (отсюда костыль `Cancel()`). `opMu` нужен только на шаг переключения, как у secure.
- **R8 (minimal, замыкание DNS) — неполно.** Если у пользователя ровно один DNS-сервер и у узла нет резолвера, sing-box берёт этот сервер (C30), а `probePlan` minimal его выбрасывает. Нужно добавить правило 5.
- **R9 (minimal) — неполно.** Один «странный» узел (ссылка на выброшенный `http_clients`, ошибка инициализации) роняет весь тестовый экземпляр. Нужна изоляция по `outbound[N]` (C27), как в `saveMerged`.
- **R10 (minimal) — окно Start/Assign закрывается.** `CREATE_SUSPENDED` → `AssignProcessToJobObject` → `ResumeThread` (C20). Запуском не проверено (U3).
- **R11 (secure, `FastestGoneMsg`) — нужно сопоставление.** `SwitchOutbound` возвращает английское `outbound %q not found or is not a proxy` (C22), его надо отображать в русский текст.
- **R12 (rich §4.7, «тесты могут сменить выбор urltest — так устроен sing-box») — недооценено.** Это видимый побочный эффект кнопки «Проверить задержку» на живом VPN (C7). В C его нет.

### Не проверено (влияет на дизайн, способ закрытия указан)

- **U1.** chi маршрутизирует по `RawPath`. Исходника нет в кэше модулей, вывод сделан по поведению chi из памяти. Как закрыть: тест с настоящим sing-box на тегах `a%41`/`aA`/`a/b`.
- **U2.** У Wintun `IfType = 53`. После C14 это уже не основание дизайна. Как закрыть: песочница.
- **U3.** `exec.Cmd` с `CREATE_SUSPENDED` + возобновление потока через Toolhelp. Как закрыть: модульный тест `process`.
- **U4.** Вложенный job под job планировщика задач.
- **U5.** `-c stdin` в версиях до 1.14.
- **U6.** Перехват порта процессом среднего уровня через `SO_REUSEADDR`. Исходим из худшего случая.
- **U7.** Тестовый экземпляр при `fakeip` в `dns.final` пользователя.
- **U8.** Время старта на 200+ узлах.
- **U9.** Файлы sing-tun читались из отдельной загрузки той же ревизии — перепроверить по модулю.

---

## 3. Синтезированный проект

### 3.0 Решение

- **Как меряем.** Задержку меряет **отдельный короткоживущий** `<Bin>\sing-box.exe run -c stdin`. Его конфиг строится в памяти из `config.json`: замыкание проверяемых outbound, нужные DNS-серверы, `certificate`, `route.auto_detect_interface`, плюс собственный `clash_api` на `127.0.0.1:<свободный порт>` с одноразовым секретом. Нет ни inbound, ни правил, ни `cache_file`, ни лога. Клиент приложения шлёт `GET /proxies/{tag}/delay` только после того, как по TCP-таблице убедился, что порт слушает именно этот PID. Процесс живёт в job-объекте «убить при закрытии».
- **Что не меняется.** Работающий VPN, путь `Manager.Start`, `config.json` и guard не трогаются. Тест работает и при выключенном VPN. Живые `urltest` пользователя он не пересчитывает (C7).
- **«Выбрать самый быстрый»** — серверная функция `domain.ChooseFastest`:
  - с запасом: текущий сервер не меняется, если хуже лучшего не больше чем на max(30 мс, 15 %);
  - при маршруте через `urltest` и при раздельной маршрутизации — отказ;
  - при маршруте через selector — подтверждение.
  
  Сохраняется существующим `SettingsService.UseOutbound` (правка маршрута в `config.json`, история, `.bak`, guard, `check`, рестарт без записи намерения). `cache.db` здесь не участвует, а `opMu` берётся только на переключение.
- **Отдельно и сразу** (шаг 0): guard перестаёт пропускать **добавление** `clash_api.external_controller` без `secret` (C21).
- **Живой Clash API на процессе VPN** (скорость, соединения, selector без рестарта) — отдельное позднее решение (§3.8). Оно включается явно из трея, по умолчанию выключено, с предварительным `check` и правилом «одна неудача — без оверлея до перезапуска приложения». Для задержки и «самого быстрого» он не нужен.

### 3.1 Кто чем владеет

```
page.html ── POST /api/latency {select,confirm} ─► webui.handleLatency (сессия, Host)
tray «Выбрать самый быстрый сервер» (шаг 2) ─────► app.handleSelectFastest (горутина; окно — после)
                        │
                        ▼
      domain.LatencyService.Test(ctx) / SelectFastest(ctx, confirm)   ← single-flight, мин. интервал, Cancel
        │ LatencySource (configfile.Editor)      │ LatencyProber (infrastructure/latency.Prober)
        │  ProbePlan(), RoutingTarget(),         │  порт, секрет, StartHelper, ownedDial,
        │  ActiveOutbound()                      │  Clash-клиент, изоляция узлов
        │                                        ▼
        │                       process.StartHelper(cmd)  ← helperPIDs + job (KILL_ON_JOB_CLOSE)
        │                                        ▼
        │                       <Bin>\sing-box.exe run -c stdin  (Dir=Data, Env=SingBoxEnv)
        └─ под opLock только: SettingsService.UseOutbound(best)  (как POST /api/switch)
```

| Файл | Что нового |
|---|---|
| `internal/infrastructure/process/helper_windows.go` | `StartHelper`, `Helper` |
| `internal/infrastructure/process/tcptable_windows.go` | `ConnOwnerPID(local, remote netip.AddrPort) (uint32, error)` — `iphlpapi.dll` через `windows.NewLazySystemDLL`, `GetExtendedTcpTable(AF_INET, TCP_TABLE_OWNER_PID_CONNECTIONS)` |
| `internal/infrastructure/configfile/latency.go` | `(*Editor).ProbePlan()`, `(*Editor).RoutingTarget()`, чистые `probePlan(cfg)`, `routingTarget(cfg)` |
| `internal/infrastructure/latency/clash.go` | Clash-клиент без платформенных зависимостей (`version`, `delay`, `escapeAll`, `measureAll`) |
| `internal/infrastructure/latency/prober_windows.go` | `Prober`, `Measure`, `ownedDial`, изоляция узлов |
| `internal/domain/latency_service.go`, `fastest.go` | модели, сервис, `ChooseFastest` |
| `internal/ui/webui/latency.go` + `server.go` + `page.html` | эндпоинты, отметки, кнопки |
| `internal/app/application.go`, `main.go` | связывание; `Cancel()` при выходе |
| `internal/config/config.go` | константы |

### 3.2 `process.StartHelper`

```go
// Helper is a long-lived run of the app's own sing-box.exe that is NOT the VPN
// (the latency test instance): registered in helperPIDs for its whole life (the
// manager neither adopts it nor kills it on Stop; a Start meanwhile starts the
// real VPN), and in a job object that kills it when this process goes away — a
// leftover elevated <Bin>\sing-box.exe would be adopted as "the VPN" by the next
// instance of the app.
type Helper struct {
	cmd  *exec.Cmd
	job  windows.Handle
	done chan struct{}
	err  error // valid once done is closed
}

func StartHelper(cmd *exec.Cmd) (*Helper, error)
func (h *Helper) PID() uint32
func (h *Helper) Done() <-chan struct{}
func (h *Helper) Err() error
func (h *Helper) Stop(timeout time.Duration) error // kill, wait, then unregister + close the job
```

Шаги `StartHelper`:

1. `cmd.SysProcAttr.CreationFlags |= windows.CREATE_SUSPENDED` (после `hideConsoleWindow`).
2. Под `helperMu`: `cmd.Start()`, затем `helperPIDs[pid]`.
3. `CreateJobObject` → `SetInformationJobObject(JobObjectExtendedLimitInformation, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE)` → `OpenProcess(PROCESS_SET_QUOTA|PROCESS_TERMINATE)` → `AssignProcessToJobObject`.
4. Главный поток находится через `CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD)` по `th32OwnerProcessID`, затем `OpenThread(THREAD_SUSPEND_RESUME)` и `ResumeThread`.
5. При любой ошибке на шагах 3–4: `TerminateProcess` (процесс ещё не выполнил ни одной инструкции sing-box), `Wait`, снятие регистрации и ошибка «Не удалось изолировать тестовый sing-box — проверка отменена».
6. Горутина `Wait` снимает регистрацию **только после** выхода процесса: PID не может быть переиспользован как «невидимый VPN».

`HelperOutput`, `Manager.Start`, `Stop` и `IsRunning` не меняются.

Запасной вариант, если `CREATE_SUSPENDED` с `exec` не заработает (U3): вариант minimal (`Assign` сразу после `Start`, окно в микросекунды, принятый риск: «Выключить → Включить» лечит).

### 3.3 Конфиг тестового экземпляра: `configfile/latency.go`

```go
func (e *Editor) ProbePlan() (*domain.ProbePlan, error)       // reads config.json, never writes
func (e *Editor) RoutingTarget() (domain.RoutingTarget, error)
func probePlan(cfg map[string]any) *domain.ProbePlan          // pure, unit-tested
func routingTarget(cfg map[string]any) domain.RoutingTarget   // pure
```

**Классификация** каждого элемента `outbounds` (в порядке конфига). Это таблица minimal с правкой secure про loopback:

| Условие | Testable | Eligible | Note |
|---|---|---|---|
| `direct`/`block`/`dns` | нет | нет | — |
| `selector` | нет | нет | «группа — проверяются её серверы» |
| `urltest` | нет | нет | «группа urltest — выбирает сервер сама» |
| `relayOnlyTypes` (`shadowtls`) | нет | нет | «промежуточный узел, только через detour» |
| тип вне `allowedOutboundTypes` | нет | нет | «тип «%s» не проверяется» |
| в замыкании есть endpoint, тип вне allow-list, отсутствующий тег, `realm`, DNS-сервер `tailscale`/`openconnect`/`openvpn`/`resolved` | нет | нет | «не проверяется: зависит от «%s»» |
| `tag == config.DPIBypassTag` | да | нет | «обход DPI без VPN — не выбирается самым быстрым» |
| прочие `localServer(o)` (информационный узел 3x-ui и т. п.) | нет | нет | «сервер на этом компьютере» |
| `relayTags(cfg, nil)[tag]` | да | нет | «промежуточный узел цепочки — не выбирается самым быстрым» |
| остальное | да | да | — |

**Замыкание** (до неподвижной точки, ключи через `foldKey`/`field`):

- outbound: `detour` и участники групп (`dependencyGraph`/`dependsOn`);
- outbound: `domain_resolver` (строка или `{server}`) → DNS-сервер;
- DNS-сервер: `detour` → outbound, `domain_resolver` → DNS-сервер;
- `route.default_domain_resolver` → DNS-сервер;
- `dns.final` → DNS-сервер;
- **правило 5 (R8):** если в `dns.servers` ровно один сервер, он включается всегда.

**Состав** (объекты копируются глубокой копией, дословно, порядок конфига):

```json
{
  "log": {"level": "warn"},
  "dns": {"…": "все поля dns пользователя, кроме rules; servers — только из замыкания"},
  "certificate": {"…": "дословно, если есть"},
  "outbounds": ["замыкание testable-узлов"],
  "route": {"auto_detect_interface": true,
            "default_interface": "<если задан>", "default_domain_resolver": "<если задан>"},
  "experimental": {"clash_api": {"external_controller": "127.0.0.1:<port>", "secret": "<64 hex>"}}
}
```

Никогда не копируются: `inbounds`, `endpoints` (v1), `route.rules`, `route.rule_set`, `dns.rules`, весь пользовательский `experimental` (его `clash_api`, `cache_file`, `external_ui`, `debug`), `log.output`, `ntp`, `services`, `http_clients`, `certificate_providers`, `network_namespaces`.

`experimental` добавляет `Prober`, а `ProbePlan.Config` его не содержит. Свой `clash_api` пользователя с тестом никак не взаимодействует: другой процесс, другой порт.

- Весь конфиг — подмножество того, что этот же бинарник уже принимает в `config.json`, плюс три поля с самых ранних версий (`auto_detect_interface`, `external_controller`, `secret`). `access_control_*` не ставится (появилось в 1.10).
- `ProbePlan.Redact(msg)` = `redactSecrets(msg, probeCfg)` плюс замена секрета Clash API. Через него проходит любой вывод тестового sing-box.

**`routingTarget`**: `Kind` — `"node"`, `"selector"`, `"urltest"` или `""`. Первая ссылка правил по порядку, затем `final`, на прокси **или** группу. `ProxyRefs` — список различных прокси, на которые указывают правила и `final`. `ActiveOutbound` не меняется (от него зависит DPI-цепочка).

### 3.4 Измерение: `infrastructure/latency`

```go
// clash.go (platform-independent)
type client struct{ base, secret string; http *http.Client }
func (c *client) version(ctx context.Context) error            // 200 ready; 401 → abort
func (c *client) delay(ctx context.Context, tag string) domain.Delay
func escapeAll(tag string) string // every byte as %XX: the request always carries RawPath
func measureAll(ctx context.Context, c *client, tags []string) map[string]domain.Delay

// prober_windows.go
type Prober struct{ binDir, dataDir string }
func New(binDir, dataDir string) *Prober
func (p *Prober) Measure(ctx context.Context, plan *domain.ProbePlan, tags []string) (map[string]domain.Delay, error)
```

**Адресация тега.** Каждый байт кодируется как `%XX`, URL строится через `url.URL{Path: tag…, RawPath: escapeAll(tag)…}`.

- Go-сервер выставляет `RawPath`, потому что кодировка нестандартная. chi маршрутизирует по нему, и его единственный `PathUnescape` даёт тег в точности.
- Так снимается проблема двойного декодирования rich F6 для `a%41`, а заодно `/`, `#`, `?`, пробелов и эмодзи.
- Зависит от U1. Если тест опровергнет: для тегов с `%XX` — отметка «имя содержит %XX — переименуйте узел».

**`Measure` по шагам:**

1. Нет `sing-box.exe` → `domain.ErrSingBoxMissing`.
2. Порт: `net.Listen("tcp4","127.0.0.1:0")` → взять порт → `Close`. Секрет — 32 байта `crypto/rand`.
3. `cmd := process.NewHiddenCommand(singBox, "run", "-c", "stdin")`, `Dir=dataDir`, `Env=process.SingBoxEnv(binDir, dataDir)`, `Stdin=bytes.NewReader(json)`. Вывод — в кольцевой буфер `StartErrorTailBytes`. Затем `h, err := process.StartHelper(cmd)` и `defer h.Stop(LatencyStopTimeout)`.
4. Готовность: `version()` каждые 100 мс, до `LatencyStartTimeout`.
5. Процесс завершился до готовности — смотрим хвост вывода:
   - `external controller listen error` → один повтор с новым портом;
   - `clash api is not included` → ошибка «собран без Clash API»;
   - `read config at stdin` или `decode config at stdin` при старой сборке без stdin (U5) → один повтор через временный файл `.latency-*.json` в папке данных (по образцу `singboxcheck`: в установленной раскладке файл только для администраторов, удаляется сразу после готовности);
   - **`initialize outbound[N]` / `outbounds[N]`** (`indexedEntry`) → узел N и всё, что через него, исключаются с отметкой «не проверяется: sing-box не смог его запустить отдельно: <Redact(причина)>», повтор. Не больше `LatencyIsolateRetries` раз, затем ошибка всей проверки.
6. **`ownedDial`** — `http.Transport.DialContext`: после каждого соединения к `127.0.0.1:<port>` вызывается `process.ConnOwnerPID(remote, local)`. Строка таблицы, где local — порт API, а remote — наш адрес, должна принадлежать `h.PID()`. Иначе соединение закрывается **до первого байта**: «Порт проверки занят другой программой — проверка прервана». Transport: `Proxy: nil`, без редиректов, ответы через `io.LimitReader` (1 МБ).
7. `measureAll`:
   - до `LatencyConcurrency` запросов `delay?timeout=LatencyProbeTimeoutMs&url=LatencyTestURL`;
   - активный узел — первым;
   - второй раунд только для ответивших, в отчёт идёт минимум;
   - коды: 200 → ok; 504 → timeout; 503 → error; 404 → error («нет в тестовом конфиге»); 401 → прервать;
   - всё, что не уложилось в `ctx`, получает статус «unfinished».
8. Лог одной строкой: `Latency: 37 of 52 answered in 9.4 s (test sing-box PID N)`. Секрет и адреса серверов в лог не пишутся.

### 3.5 Домен: `latency_service.go`, `fastest.go`

```go
type LatencyStatus string // "ok" | "timeout" | "error" | "unfinished" | "skipped"
type Delay struct{ Ms int; Status LatencyStatus }
type LatencyCandidate struct{ Tag, Type string; Testable, Eligible bool; Note string }
type ProbePlan struct {
	Config     map[string]any      // without "experimental"
	Candidates []LatencyCandidate
	Redact     func(string) string
}
type RoutingTarget struct {
	Kind      string   // "node" | "selector" | "urltest" | ""
	Tag       string
	ProxyRefs []string // distinct proxies route rules / final point at
}
type LatencySource interface {
	ProbePlan() (*ProbePlan, error)
	RoutingTarget() (RoutingTarget, error)
	ActiveOutbound() (string, error)
}
type LatencyProber interface {
	Measure(ctx context.Context, plan *ProbePlan, tags []string) (map[string]Delay, error)
}

type LatencyResult struct {
	Tag      string        `json:"tag"`
	Type     string        `json:"type"`
	DelayMs  int           `json:"delay_ms,omitempty"`
	Status   LatencyStatus `json:"status"`
	Eligible bool          `json:"eligible"`
	Note     string        `json:"note,omitempty"`
}
type LatencyReport struct {
	Tested   time.Time       `json:"tested"`
	Answered int             `json:"answered"`
	Total    int             `json:"total"`
	Active   string          `json:"active,omitempty"`
	Fastest  string          `json:"fastest,omitempty"`
	Results  []LatencyResult `json:"results"`
}
type FastestOutcome struct {
	Tag, Previous     string
	DelayMs, PrevMs   int
	Switched, Restarted, NeedsConfirm bool
	DPIWas            string // the DPI chain stayed on the previous node
	Message           string // ready Russian text
}

var ErrLatencyBusy, ErrLatencyTooSoon error

func NewLatencyService(src LatencySource, prober LatencyProber,
	use func(tag string) (restarted bool, err error), opLock sync.Locker) *LatencyService
func (s *LatencyService) Test(ctx context.Context) (*LatencyReport, error)
func (s *LatencyService) SelectFastest(ctx context.Context, confirm bool) (*LatencyReport, *FastestOutcome, error)
func (s *LatencyService) Last() *LatencyReport // in memory only; nothing persisted
func (s *LatencyService) Cancel()

func ChooseFastest(r *LatencyReport, rt RoutingTarget, confirm bool) FastestOutcome // pure
```

**Поведение `Test`:**

- одна проверка за раз (`TryLock` → `ErrLatencyBusy`);
- между проверками не меньше `LatencyMinIntervalSeconds` (`ErrLatencyTooSoon`);
- дедлайн `LatencyTestMaxSeconds`;
- ошибки проходят через `withSetupHint`;
- без testable-узлов отчёт возвращается сразу, процесс не запускается.

**`ChooseFastest`, по порядку:**

1. `rt.Kind == "urltest"` → отказ.
2. `len(rt.ProxyRefs) ≥ 2` → отказ.
3. `best` = минимум среди `Eligible && ok`; при равенстве — порядок конфига.
4. `best` не найден → отказ «никто не ответил».
5. Активный ответил, и `active ≤ best + max(FastestKeepMarginMs, best·FastestKeepMarginPct/100)` → `Keep`, ничего не сохраняется.
6. `rt.Kind == "selector"` и `!confirm` → `NeedsConfirm`.
7. Иначе переключение.

**Шаг переключения в `SelectFastest`:**

- `opLock.Lock()` → `use(best)`, это `SettingsService.UseOutbound`;
- ошибку «not found or is not a proxy» сервис превращает в текст «пропал из конфига» (R11);
- `DPIWas` берётся из старого активного узла с `detour == dpi-bypass`;
- `opLock.Unlock()`.

Сам замер `opMu` **не держит** (R7).

### 3.6 Web UI

**Эндпоинты** регистрируются всегда. Без `SetLatency` ответ — `fail("проверка задержки недоступна")`; страница прячет кнопки по полю `latency: true` в `GET /api/config`.

| Метод, путь | Сессия | Тело | Ответ |
|---|---|---|---|
| `POST /api/latency` | `auth` | `{"select": false}` или `{"select": true, "confirm": bool}` | `200 {"report": LatencyReport, "fastest": FastestOutcome\|null}`; `400 {"error"}` |
| `GET /api/latency` | `auth` | — | `{"report": LatencyReport\|null}` — последний отчёт (в том числе запущенный из трея) |

- Закрытая вкладка отменяет проверку через `r.Context()`.
- Ни один ответ не содержит секрета, порта, адресов серверов или URL подписок.
- URL теста — константа, параметра для него нет.

**Страница, раздел «Активный сервер»** (`#outbound-list` и `#switch-btn` остаются, тест в песочнице на них опирается):

- кнопки: «Проверить задержку» (вторичная) и «Выбрать самый быстрый» (шаг 2);
- в строке `renderOutbounds` — `span.latency` через `textContent`:
  - «84 мс» классом `fast` (< 200), `mid` (< 500) или `slow`;
  - «нет ответа» (timeout), «ошибка», «не успели»;
  - для skipped и неподходящих — `note`.
- подпись: «Задержка — время до ответа https://www.gstatic.com через сервер (подключение, рукопожатие и один запрос; так же меряет группа urltest). Каждый сервер проверяется напрямую, мимо правил маршрутизации, отдельным временным sing-box — работающий VPN не затрагивается. Проверка подключается ко всем серверам списка с вашего адреса.»

| Случай | Текст |
|---|---|
| идёт проверка | «Проверяю задержку серверов… (до 30 с)» |
| итог | «Проверено в %s: ответили %d из %d. Быстрее всех — «%s» (%d мс)» |
| переключено | «Выбран самый быстрый — «%s» (%d мс; был «%s» — %s).» + существующий `restartedSuffix(d)` |
| текущий годится | «Текущий сервер «%s» и так среди самых быстрых (%d мс; лучший — «%s», %d мс). Ничего не изменено.» |
| никто не ответил | «Ни один сервер не ответил — активный сервер не изменён.» |
| urltest | «Трафик идёт через группу urltest «%s» — она сама выбирает самый быстрый сервер. Ничего не изменено.» |
| раздельная маршрутизация | «Правила маршрутизации ведут трафик на разные серверы (%s) — «самый быстрый» направил бы всё на один. Выберите сервер вручную.» |
| маршрут через selector (`confirm()`) | «Сейчас трафик идёт через группу «%s». «Выбрать самый быстрый», как и выбор вручную, направит его прямо на «%s» (группа останется в конфиге). Продолжить?» |
| DPI | «Обход DPI был включён для «%s». Для нового сервера включите его заново (раздел «Обход DPI»).» |
| пропал | «Сервер «%s» пропал из конфига во время проверки (обновилась подписка?) — повторите.» |
| занято / часто | «Проверка задержки уже идёт» / «Повторите проверку через несколько секунд» |
| нет API в сборке | «Ваш sing-box собран без Clash API (with_clash_api) — проверка задержки недоступна» |
| не стартовал | «Тестовый sing-box не запустился: %s» |
| не ответил | «Тестовый sing-box не ответил за %d с» |
| чужой порт | «Порт проверки занят другой программой — проверка прервана» |
| изоляция | «Не удалось изолировать тестовый sing-box — проверка отменена» |
| отмена | «Проверка прервана» |

### 3.7 Трей (шаг 2), app, main

- Пункт «Выбрать самый быстрый сервер» с подсказкой «Проверить задержку всех серверов и переключиться на самый быстрый» встаёт **после** `appUpdateItem`. Новые id: DPI 13, автозапуск 14, «Выход» **16**. В `lifecycle-test.ps1` меняется только `$menuQuit = 16`.
- `handleSelectFastest` в горутине: `SelectFastest(ctx, false)`. При `NeedsConfirm` в трее — отказ с текстом «Трафик идёт через группу «%s» — выберите сервер в «Настройках»». Всплывающее окно «Самый быстрый сервер» показывается без замков.
- `Application.SetLatency(svc)`. `RequestQuit` и `RelaunchAfterUpdate` вызывают `svc.Cancel()`. Это для быстроты: `opMu` проверка не держит, а job всё равно убьёт помощника при выходе.
- `main.go`:

```go
latencySvc := domain.NewLatencyService(configEditor, latency.New(layout.Bin, layout.Data),
	settingsService.UseOutbound, application.OpLock())
settingsUI.SetLatency(latencySvc)
application.SetLatency(latencySvc)
```

**Константы (`config.go`):**

```go
LatencyTestURL            = "https://www.gstatic.com/generate_204"
LatencyProbeTimeoutMs     = 5000
LatencyConcurrency        = 8
LatencyRounds             = 2
LatencyStartTimeout       = 10 // s, test instance API ready
LatencyTestMaxSeconds     = 30
LatencyStopTimeout        = 5  // s
LatencyMinIntervalSeconds = 10
LatencyIsolateRetries     = 3
FastestKeepMarginMs       = 30
FastestKeepMarginPct      = 15
```

### 3.8 Как сохраняется выбор и с чем он взаимодействует

- **Хранение.** `SwitchOutbound` пишет в `config.json`: правила и `route.final`, `.bak` + `config-history/` (выбор можно откатить), guard, зависимости, `sing-box check`, затем `RestartIfRunning` (без записи намерения). При выключенном VPN — свежий бюджет монитора. Выбор переживает перезагрузку. Если быстрейший уже активный, запись не делается.
- **Почему не selector + `cache.db`.** Нужен живой API на процессе VPN. Сохранённый в `cache.db` выбор важнее `default` (C8) и незаметно расходится со страницей и откатом истории. Без `cache_file` выбор теряется. Перенаправление маршрута от `cache.db` не зависит.
- **Подписки.** Обновление ждёт `opMu` только на шаге переключения. Узел, переименованный провайдером, сохраняет ссылки (`pairRenamed`). Удалённый узел заменяется уцелевшим (`pruneOutboundReferences`), выбор заново не делается. Отчёт привязан к тегам: исчезнувшие просто не рисуются. Отдельный экземпляр строится из текущего конфига, поэтому расхождения «конфиг ↔ работающий процесс» после переименований без рестарта (C23) здесь нет.
- **Группы.** `urltest` пользователя тест не трогает (C7). Группа в роли `detour` копируется без `cache_file`, так что в тесте она идёт через `default` или первого участника: возможное расхождение с живым VPN, редкость.
- **DPI (режим A).** Узел с `detour: dpi-bypass` меряется через zapret, остальные — напрямую: сравнение для него неравное (это видно по примечанию). Цепочку переключение не переносит, отсюда `DPIWas`.
- **Фоновой проверки нет.** Только по нажатию: никаких автоматических массовых подключений к серверам.

### 3.9 Безопасность

| Кто | Что может после изменения | Что нового |
|---|---|---|
| Владелец сессии web UI (в том числе программа без прав, перехватившая ссылку входа) | запускать проверку (single-flight, интервал 10 с, ≤ 30 с), видеть задержки, «самый быстрый» = `/api/switch`, доступный ему и сегодня | фактически ничего: URL фиксирован (нет SSRF через повышенный sing-box), секрета, порта и адресов в ответах нет, текст ошибок проходит `Redact` |
| Программа без прав, без сессии | подключиться к порту API на время проверки → 401. Занять порт до старта → сбой теста, VPN не затронут. Перехватить порт через `SO_REUSEADDR` (U6) → `ownedDial` отказывает до отправки секрета | секрет передаётся через stdin в повышенный процесс (NO_READ_UP), на диск и в командную строку не попадает |
| Веб-страницы (rebinding, CORS `*`) | без секрета → 401; `external_ui` нет | — |
| Другие пользователи машины | как программа без прав | — |
| Утечка секрета (худший случай) | на ≤ 30 с: delay-тесты к https-URL через узлы пользователя, DNS-запросы, список имён | файлов не пишет: `/upgrade/ui` → 404, `PUT /configs` ничего не делает (C5) |
| Сам тестовый процесс | исполняет подмножество того, что уже исполняет VPN: без inbound, правил, rule-set, служб, логов и кэша. `tor` и типы вне allow-list не копируются даже из ручного конфига | — |
| Приватность | каждый сервер видит подключение с реального IP, провайдер и DPI видят пачку подключений к VPN-серверам | сказано в подписи; проверка только по нажатию, конкурентность 8, минимальный интервал |

**Шаг 0 (guard, независим от остального).** Новый или изменённый `clash_api` с непустым `external_controller` без `secret` (или с секретом короче 16 символов) отклоняется. Отказ: «experimental.clash_api: external_controller без secret». Новое `access_control_allow_private_network: true` тоже отклоняется. То, что администратор написал руками, остаётся (сравнение по элементам, как сейчас). Заодно `secret` добавляется в `secretKeys`.

### 3.10 Отказы и пограничные случаи

| Ситуация | Поведение |
|---|---|
| VPN с TUN и `strict_route` | `auto_detect_interface` + тот же exe (C14–C16): набор идёт мимо TUN, WFP пропускает. В песочнице проверяется `LocalAddress` соединений помощника |
| VPN выключен | меряется напрямую, как ходил бы сам sing-box |
| VPN включают или выключают во время проверки | разрешено. Помощник невидим для `findProcesses`, `Start` поднимает настоящий VPN, `Stop` помощника не трогает |
| Порт занят (гонка) | один повтор, затем ошибка; VPN не затронут |
| Сборка без `with_clash_api`, старая без stdin | понятная ошибка или временный файл в папке данных |
| Один узел не инициализируется отдельно | исключается по `outbound[N]`, остальные меряются |
| Сломан сам `config.json` | тестовый экземпляр падает с той же (отредактированной) ошибкой — тоже диагноз |
| `dns.final` — `fakeip`, у узла нет резолвера (U7) | возможна «ошибка» для этого узла; проверяется в песочнице |
| 200+ узлов | дедлайн 30 с; что не успели — «не успели»; активный узел первым |
| Трей падает, выход, самообновление | job убивает помощника; `Cancel()` для скорости |
| Обновление подписки или sing-box во время проверки | не ждут: проверка не держит `opMu`; переименованный работающий exe Windows разрешает |

### 3.11 Тесты

1. **`configfile/latency_test.go`** (чистые функции):
   - каждая строка классификации;
   - замыкание: detour, группа как detour, DNS `detour`, `domain_resolver` строкой и объектом, `default_domain_resolver`, `dns.final`, правило 5, ключи `Detour`/`DOMAIN_RESOLVER`;
   - объекты копируются дословно (`reflect.DeepEqual`);
   - в результате нет `inbounds`, `route.rules`, `rule_set`, `dns.rules`, пользовательского `experimental`, `log.output`, `ntp`, `endpoints`, `http_clients`;
   - `config.json` побайтно не изменился, нет `.bak` и записи в истории;
   - `Redact` вычищает пароль, uuid и секрет;
   - `routingTarget`: node, selector, urltest, раздельная маршрутизация.
2. **`latency/clash_test.go`** — httptest как Clash API, который **повторяет двойное декодирование** chi при пустом `RawPath`:
   - `escapeAll` для `a%41`, `aA`, `a/b`, кириллицы и эмодзи;
   - 401 → прерывание; 200/503/504/404;
   - не больше 8 запросов одновременно (счётчик в обработчике);
   - второй раунд и минимум; дедлайн → unfinished; отмена ctx;
   - в ошибках клиента нет URL и заголовков.
3. **`process/helper_windows_test.go`** — подставной `sing-box.exe` в новом режиме `TRAY_SINGBOX_FAKE_MODE=serve`:
   - помощник не виден `Manager.IsRunning`; `Start` запускает свой VPN рядом; `Stop` помощника не убивает;
   - закрытие job убивает процесс;
   - регистрация снимается только после выхода;
   - процесс, созданный в `CREATE_SUSPENDED`, не начинает работу до `Assign` (подставной пишет файл-маркер при старте);
   - `ConnOwnerPID` на своём слушателе.
   
   Запускать в тех же условиях, что и остальные тесты `process` (см. заметки разработчика про антивирус).
4. **`latency/prober_windows_test.go`** — `SINGBOX_REAL_DIR`, не в `-short`; `sing-box.exe` копируется во временный Bin:
   - офлайн: узел `socks` на `192.0.2.1:1080` → timeout или error;
   - готовность и `ownedDial`;
   - занятый порт → повтор;
   - узел, которому нужен невыброшенный ресурс → изоляция;
   - теги `a%41` и `aA` различаются (закрывает U1);
   - после теста во временном Bin не осталось процесса.
   
   Порядок задержек — только в подтесте с сетью (gstatic), из-за R1.
5. **`domain/latency_service_test.go`** — фейки:
   - `ChooseFastest` табличный: запас (мс и %), keep, urltest, раздельная маршрутизация, selector без и с `confirm`, никто не ответил, только неподходящие, ничья;
   - `ErrLatencyBusy`/`ErrLatencyTooSoon`, `Cancel`;
   - `opLock` взят **только** вокруг `use` и `use` вызван один раз;
   - `DPIWas`.
6. **`webui/latency_test.go`**: без сессии — 401; в теле ответа нет секрета и порта из фейка (grep); без `SetLatency` — ошибка; параметра URL нет.
7. **Песочница, `lifecycle-test.ps1 -Phase latency`** (сетевой, после `install`):
   - второй sing-box из **другой** папки как `mixed` на IP песочницы (не на loopback, иначе `localServer`) + .NET-ретранслятор с задержкой 300 мс + мёртвый `192.0.2.1`;
   - через DevTools `POST /api/latency`: живой ok, eligible, мёртвый timeout;
   - PID и статус VPN не изменились; после проверки ровно один `sing-box.exe` по пути Bin;
   - `Stop-Process` трея во время проверки → помощник исчез;
   - на TUN-конфиге: `Get-NetTCPConnection -OwningProcess <помощник>` → `LocalAddress` сетевой карты, а не TUN; записать `(Get-NetAdapter -InterfaceDescription 'Wintun*').InterfaceType` (U2);
   - `{select:true}` → `route.final` изменился, новый PID VPN, намерение то же, `.bak` и история; повтор → «и так среди самых быстрых», тот же PID;
   - с `-Uac`: в `Win32_Process.CommandLine` помощника нет секрета (`run -c stdin`);
   - пункт трея (id 11) и `$menuQuit = 16` — на шаге 2.

### 3.12 План поставки

| Шаг | Что входит | Самостоятельная ценность | Готово, когда |
|---|---|---|---|
| **0** (≈ день, параллельно) | ужесточение guard (§3.9), `secret` в `secretKeys`, тесты | закрывает сегодняшнюю дыру: первый конфиг или откат истории может открыть API sing-box любой локальной программе | тесты guard |
| **1 — MVP «Проверить задержку»** | `StartHelper` + `ConnOwnerPID`, `ProbePlan`/`RoutingTarget`, `infrastructure/latency`, `LatencyService.Test`/`Last`/`Cancel`, `POST`/`GET /api/latency` (без `select`), отметки и подпись на странице, связывание, константы, этап песочницы `latency` (части без «самого быстрого»), CLAUDE.md и TODO.md | видно, какой сервер жив и быстр; переключение — существующей кнопкой «Использовать выбранный». Только чтение: ни одной записи конфига, путь запуска VPN не тронут | тесты 1–4, 6; песочница: VPN не мигнул, помощник умирает вместе с треем |
| **2 — «Выбрать самый быстрый»** | `ChooseFastest`, `SelectFastest` (`opLock` на переключение), подтверждение для selector, отказы urltest и раздельной маршрутизации, `DPIWas`, пункт трея, `$menuQuit = 16` | одна кнопка | тест 5, песочница `select` |
| **3 (по желанию)** | «самый быстрый внутри маршрутной группы selector» (кандидаты — её участники); флажок «если активный сервер исчез из подписки — выбрать самый быстрый» (только по согласию: это рестарт без участия пользователя) | — | — |
| **4 — живой Clash API (отдельное решение)** | скорость, соединения, selector без рестарта: §3.13 | — | — |

### 3.13 Шаг 4: правила для живого API на процессе VPN

Основа — secure, с поправками:

- **Включение** — только флажком в трее (доверенный канал) «Статистика sing-box (Clash API)». Хранится в админском `<Data>\tray-settings.json`. По умолчанию **выключено**: вопрос мейнтейнеру из rich закрыт в пользу безопасности.
- **Политика пропуска.** Оверлея нет, если в `config.json`:
  - есть `experimental.clash_api` в любом написании ключей (потоковый декодер, повторы ключей учитываются; secure);
  - есть `clash_mode` в `route.rules`/`dns.rules`, включая логические (C9);
  - `experimental` или `clash_api` не объект;
  - файл не читается строгим JSON.
- **Предварительная проверка.** `sing-box check -c config.json -c <overlay>` через `HelperOutput`, один раз на пару «штамп exe + штамп config.json» (C12). Она ловит слияние, разбор и отсутствие тега сборки **без** подъёма TUN. Остаётся только риск порта.
- **Порт.** Случайный в 20000–45000 с пробной привязкой (secure). Файл `.tray-clash-api.json` пишется `paths.WriteAdminOnlyFile` и сортируется раньше `config.json`.
- **Отказ при старте.** `external controller listen error` в пределах grace → в том же `Start` один повтор **без** оверлея. Поздний отказ по вине оверлея → оверлей выключается до перезапуска приложения сразу, с первого раза. Так монитор теряет не больше одной попытки.
- **Доступ.** Проверка собеседника по PID на каждом соединении. Странице — только типизированные операции. Для опросных эндпоинтов — `authPassive` (rich): опрос не продлевает сессию.
- **Selector без рестарта.** `SetSelectorDefault` — обычное сохранение с историей, **без исключения** rich. Затем `PUT /proxies/{g}`. После каждого старта — сверка `now ↔ default`, потому что `cache.db` важнее `default` (C8).
- **Расходы.** Учёт трафика и форматирование всего лога (C10, R5) измеряются в песочнице до включения по умолчанию.
- **Альтернатива без API.** Скорость в подсказке трея можно взять из счётчиков TUN-адаптера (`GetIfEntry2` по `interface_name`). Для конфигов без TUN этого не будет; не проверено.

### 3.14 Допущения итогового проекта

- **Проверены:** C1–C30 выше.
- **Не проверены** и закрываются тестами шага 1: U1 (chi `RawPath`), U2 (тип Wintun; после C14 не несущее допущение), U3 (`CREATE_SUSPENDED` с `exec`), U4 (вложенный job), U5 (`-c stdin` в старых версиях), U6 (перехват порта; закрыт `ownedDial`), U7 (`fakeip`), U8 (время старта на больших конфигах), U9 (происхождение файлов sing-tun).

Ни одно из непроверенных допущений не может помешать запуску VPN: в худшем случае не удаётся проверка задержки.