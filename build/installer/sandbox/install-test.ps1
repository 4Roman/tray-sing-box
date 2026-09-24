# Installer test, run INSIDE Windows Sandbox by run.ps1 (Windows PowerShell
# 5.1 — no pwsh-only syntax here). Everything happens in the disposable
# sandbox:
#   1. a portable copy with autostart and a running VPN (the user's situation
#      before the installer existed);
#   2. silent install over it: the running copy quits, --migrate takes it
#      over, the task is repointed, the installed copy is relaunched and
#      restores the VPN from Program Files;
#   3. silent upgrade: the running instance quits and is relaunched, sing-box
#      keeps running (same PID);
#   4. silent uninstall: processes, task, registry intent and program files
#      gone, data kept;
#   5. reinstall over the kept data, the task launches the app (elevated,
#      no UAC prompt);
#   6. uninstall with /DELETEDATA=1 while a portable copy runs: the portable
#      copy survives, the data dir is deleted.
# Results: <this folder>\results (summary.txt, trace.txt, logs). The sandbox
# shuts itself down at the end unless <this folder>\keep-open exists.
param([switch]$Elevated)

$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent $PSCommandPath
$res = Join-Path $root 'results'
New-Item -ItemType Directory -Force $res | Out-Null
$trace = Join-Path $res 'trace.txt'

function Log([string]$m) {
    Add-Content -Path $trace -Encoding UTF8 -Value ('{0:HH:mm:ss} {1}' -f (Get-Date), $m)
}

$script:checks = New-Object System.Collections.ArrayList
function Check([string]$name, [bool]$ok, [string]$detail = '') {
    [void]$script:checks.Add([pscustomobject]@{ Name = $name; OK = $ok; Detail = $detail })
    $mark = 'FAIL'
    if ($ok) { $mark = 'PASS' }
    Log "$mark $name  $detail"
}

function WriteSummary([string]$note = '') {
    $fail = @($script:checks | Where-Object { -not $_.OK })
    $head = 'RESULT: ALL PASSED'
    if ($fail.Count -gt 0) { $head = "RESULT: $($fail.Count) FAILED" }
    if ($note) { $head = "$head ($note)" }
    $lines = @("$head, $($script:checks.Count) checks")
    foreach ($c in $script:checks) {
        $mark = 'FAIL'
        if ($c.OK) { $mark = 'PASS' }
        $lines += ('{0} {1}  {2}' -f $mark, $c.Name, $c.Detail)
    }
    $lines | Out-File -FilePath (Join-Path $res 'summary.txt') -Encoding UTF8
}

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Log "user $([Environment]::UserName), elevated $isAdmin, $([Environment]::OSVersion.VersionString)"
if (-not $isAdmin) {
    if ($Elevated) {
        Log 'still not elevated after RunAs'
        WriteSummary 'ABORTED: not elevated'
        exit 1
    }
    Log 'not elevated: relaunching with RunAs (confirm the UAC prompt inside the sandbox)'
    Start-Process powershell.exe -Verb RunAs -ArgumentList @('-ExecutionPolicy', 'Bypass', '-File', $PSCommandPath, '-Elevated')
    exit 0
}

# --- helpers ---------------------------------------------------------------

# Processes by FULL image path (the same exe name runs from two folders here)
function Procs([string]$exe) {
    $name = Split-Path -Leaf $exe
    @(Get-CimInstance Win32_Process -Filter "Name='$name'" |
        Where-Object { $_.ExecutablePath -and ($_.ExecutablePath -ieq $exe) })
}

function Running([string]$exe) { return (@(Procs $exe).Count -gt 0) }

function FirstPid([string]$exe) {
    $p = @(Procs $exe)
    if ($p.Count -eq 0) { return 0 }
    return [int]$p[0].ProcessId
}

function WaitFor([scriptblock]$cond, [int]$seconds) {
    $deadline = (Get-Date).AddSeconds($seconds)
    while ((Get-Date) -lt $deadline) {
        if (& $cond) { return $true }
        Start-Sleep -Milliseconds 500
    }
    return [bool](& $cond)
}

# Not Start-Process -Wait: it also waits for every child process — the setup
# starts the tray app, which never exits
function RunWait([string]$file, [string[]]$argList, [int]$seconds = 300) {
    $p = Start-Process -FilePath $file -ArgumentList $argList -PassThru
    $null = $p.Handle # keeps ExitCode readable after the exit
    if (-not $p.WaitForExit($seconds * 1000)) {
        Log "$file did not exit within $seconds s"
        return -999
    }
    return $p.ExitCode
}

function TaskInfo {
    $out = & schtasks.exe /Query /TN SingBoxTray /XML 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $out) { return $null }
    $x = [xml]($out -join "`n")
    return [pscustomobject]@{
        Command  = [string]$x.Task.Actions.Exec.Command
        RunLevel = [string]$x.Task.Principals.Principal.RunLevel
        Version  = [string]$x.Task.RegistrationInfo.Version
    }
}

function TaskText($t) {
    if (-not $t) { return 'no task' }
    return "$($t.Command) $($t.RunLevel) v$($t.Version)"
}

function Intent {
    $v = Get-ItemProperty -Path 'HKCU:\Software\SingBoxTray' -Name VPNRunning -ErrorAction SilentlyContinue
    if ($v) { return [int]$v.VPNRunning }
    return $null
}

function Listening {
    return [bool](Get-NetTCPConnection -LocalPort 2080 -State Listen -ErrorAction SilentlyContinue)
}

# The last session of an app log (after the last "Application started")
function LastSession([string]$logPath) {
    if (-not (Test-Path $logPath)) { return '' }
    $text = Get-Content -Path $logPath -Raw -Encoding UTF8
    $i = $text.LastIndexOf('=== Application started ===')
    if ($i -lt 0) { return $text }
    return $text.Substring($i)
}

function SaveLog([string]$src, [string]$name) {
    if (Test-Path $src) { Copy-Item -Path $src -Destination (Join-Path $res $name) -Force }
}

$portable = 'C:\Portable'
$pf = Join-Path $env:ProgramFiles 'SingBoxTray'
$pd = Join-Path $env:ProgramData 'SingBoxTray'
$setup = Join-Path $root 'setup.exe'
$dlls = @(Get-ChildItem -Path (Join-Path $root 'payload') -Filter '*.dll' | ForEach-Object { $_.Name })
$silent = @('/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART')

try {
    # --- 1. portable copy, autostart, VPN running ---------------------------
    Log '--- 1. portable copy with autostart and a running VPN'
    New-Item -ItemType Directory -Force $portable | Out-Null
    Copy-Item -Path (Join-Path $root 'payload\*') -Destination $portable -Force

    $code = RunWait "$portable\tray-sing-box.exe" @('--enable-autostart') 60
    Check '1.1 portable --enable-autostart exits 0' ($code -eq 0) "exit $code"
    $t = TaskInfo
    Check '1.2 task launches the portable exe with HighestAvailable' ($t -and $t.Command -ieq "$portable\tray-sing-box.exe" -and $t.RunLevel -eq 'HighestAvailable') (TaskText $t)

    if (-not (Test-Path 'HKCU:\Software\SingBoxTray')) { New-Item -Path 'HKCU:\Software\SingBoxTray' | Out-Null }
    New-ItemProperty -Path 'HKCU:\Software\SingBoxTray' -Name VPNRunning -PropertyType DWord -Value 1 -Force | Out-Null
    Start-Process -FilePath "$portable\tray-sing-box.exe"
    $ok = WaitFor { (Running "$portable\sing-box.exe") -and (Listening) } 60
    Check '1.3 portable app restored the VPN (its sing-box listens on 2080)' $ok
    SaveLog "$portable\tray-sing-box.log" '1-portable.log'

    # --- 2. install over it --------------------------------------------------
    Log '--- 2. silent install over the running portable copy'
    $code = RunWait $setup ($silent + @("/LOG=$res\2-setup.log")) 300
    Check '2.1 setup exits 0' ($code -eq 0) "exit $code"
    Check '2.2 portable tray app quit' (-not (Running "$portable\tray-sing-box.exe"))
    Check '2.3 portable sing-box ended by the takeover' (-not (Running "$portable\sing-box.exe"))
    Check '2.4 exe installed' (Test-Path "$pf\tray-sing-box.exe")
    $missing = @(@('sing-box.exe') + $dlls | Where-Object { -not (Test-Path (Join-Path $pf $_)) })
    Check '2.5 sing-box.exe and its DLLs taken over into Program Files' ($missing.Count -eq 0) ("missing: " + ($missing -join ', '))
    Check '2.6 config.json taken over into ProgramData' (Test-Path "$pd\config.json")
    Check '2.7 no config.json next to the installed exe' (-not (Test-Path "$pf\config.json"))
    $ok = WaitFor { (Running "$pf\tray-sing-box.exe") -and (Running "$pf\sing-box.exe") -and (Listening) } 90
    Check '2.8 relaunched installed app restored the VPN from Program Files' $ok
    $t = TaskInfo
    Check '2.9 task repointed at the installed exe' ($t -and $t.Command -ieq "$pf\tray-sing-box.exe" -and $t.RunLevel -eq 'HighestAvailable' -and $t.Version -eq '2') (TaskText $t)
    Check '2.10 intent still 1' ((Intent) -eq 1) "intent $(Intent)"
    Check '2.11 portable folder left intact' ((Test-Path "$portable\config.json") -and (Test-Path "$portable\sing-box.exe") -and (Test-Path "$portable\tray-sing-box.exe"))

    $sidType = [Security.Principal.SecurityIdentifier]
    $acl = Get-Acl -Path $pd
    $owner = $acl.GetOwner($sidType).Value
    $allowed = @('S-1-5-18', 'S-1-5-32-544', 'S-1-3-4') # SYSTEM, Administrators, OWNER RIGHTS
    $foreign = @($acl.GetAccessRules($true, $true, $sidType) | Where-Object { $allowed -notcontains $_.IdentityReference.Value })
    $foreignText = ($foreign | ForEach-Object { "$($_.IdentityReference.Value):$($_.FileSystemRights)" }) -join ', '
    Check '2.12 data dir: owner Administrators, protected DACL, SYSTEM/Administrators/OWNER RIGHTS only' ($owner -eq 'S-1-5-32-544' -and $acl.AreAccessRulesProtected -and $foreign.Count -eq 0) "owner $owner, protected $($acl.AreAccessRulesProtected), others: $foreignText"
    & icacls.exe $pd | Out-File -FilePath (Join-Path $res '2-icacls.txt') -Encoding UTF8
    Check '2.13 installed app runs the installed layout' ((LastSession "$pd\tray-sing-box.log") -match 'Layout: installed')
    SaveLog "$pd\tray-sing-box.log" '2-installed.log'

    # --- 3. upgrade over the running installed copy --------------------------
    Log '--- 3. silent upgrade'
    $sbPid = FirstPid "$pf\sing-box.exe"
    $trayPid = FirstPid "$pf\tray-sing-box.exe"
    $code = RunWait $setup ($silent + @("/LOG=$res\3-setup.log")) 300
    Check '3.1 setup exits 0' ($code -eq 0) "exit $code"
    $ok = WaitFor { $n = FirstPid "$pf\tray-sing-box.exe"; ($n -ne 0) -and ($n -ne $trayPid) } 60
    Check '3.2 old instance quit, new one started' $ok "before $trayPid, after $(FirstPid "$pf\tray-sing-box.exe")"
    Start-Sleep -Seconds 8 # the new instance adopts sing-box, the monitor ticks
    $sbNow = @(Procs "$pf\sing-box.exe")
    Check '3.3 sing-box kept running through the upgrade (same PID)' ($sbPid -ne 0 -and $sbNow.Count -eq 1 -and [int]$sbNow[0].ProcessId -eq $sbPid) "before $sbPid, after $(($sbNow | ForEach-Object { $_.ProcessId }) -join ',')"
    Check '3.4 VPN still listening' (Listening)
    Check '3.5 new instance adopted the running sing-box' ((LastSession "$pd\tray-sing-box.log") -match 'already running, not starting new instance')
    $t = TaskInfo
    Check '3.6 task still launches the installed exe' ($t -and $t.Command -ieq "$pf\tray-sing-box.exe") (TaskText $t)
    SaveLog "$pd\tray-sing-box.log" '3-installed.log'

    # --- 4. uninstall, data kept ----------------------------------------------
    Log '--- 4. silent uninstall (data kept)'
    $code = RunWait "$pf\unins000.exe" ($silent + @("/LOG=$res\4-uninstall.log")) 300
    Log "unins000 exit $code"
    # The uninstaller hands over to a copy of itself in TEMP
    $ok = WaitFor { -not (Test-Path "$pf\unins000.exe") } 180
    Check '4.1 uninstaller finished' $ok
    Check '4.2 no process of the installation left' ((-not (Running "$pf\tray-sing-box.exe")) -and (-not (Running "$pf\sing-box.exe")))
    $left = @(Get-ChildItem -Path $pf -Force -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
    Check '4.3 program files cleaned' ($left.Count -eq 0) ("left: " + ($left -join ', '))
    Check '4.4 task deleted' (-not (TaskInfo))
    Check '4.5 registry intent deleted' (-not (Test-Path 'HKCU:\Software\SingBoxTray'))
    Check '4.6 data kept without /DELETEDATA' (Test-Path "$pd\config.json")
    Check '4.7 portable folder still intact' ((Test-Path "$portable\config.json") -and (Test-Path "$portable\sing-box.exe"))

    # --- 5. reinstall over the kept data, launch through the task -------------
    Log '--- 5. reinstall, start through the task'
    $code = RunWait $setup ($silent + @("/LOG=$res\5-setup.log")) 300
    Check '5.1 setup exits 0' ($code -eq 0) "exit $code"
    Check '5.2 a silent install with nothing running launches nothing' (-not (Running "$pf\tray-sing-box.exe"))
    $t = TaskInfo
    Check '5.3 task registered for the installed exe' ($t -and $t.Command -ieq "$pf\tray-sing-box.exe" -and $t.RunLevel -eq 'HighestAvailable') (TaskText $t)
    # Expected: the uninstall removed it and there is no takeover source now —
    # "Обновить sing-box" downloads it (the updater handles a missing binary)
    Log "info: sing-box.exe after reinstall over kept data: $(Test-Path "$pf\sing-box.exe")"
    & schtasks.exe /Run /TN SingBoxTray | Out-Null
    $ok = WaitFor { Running "$pf\tray-sing-box.exe" } 30
    Check '5.5 the task starts the installed app (elevated, no UAC prompt)' $ok
    Start-Sleep -Seconds 4
    Check '5.6 restore reads the deleted intent as off' ((LastSession "$pd\tray-sing-box.log") -match 'Restoring VPN state: false')

    # --- 6. uninstall with /DELETEDATA=1 while a portable copy runs -----------
    Log '--- 6. uninstall with /DELETEDATA=1, a portable copy running'
    $code = RunWait "$pf\tray-sing-box.exe" @('--quit') 60
    Check '6.1 --quit ends the installed instance (exit 0)' ($code -eq 0) "exit $code"
    Start-Process -FilePath "$portable\tray-sing-box.exe"
    $ok = WaitFor { Running "$portable\tray-sing-box.exe" } 30
    Start-Sleep -Seconds 3
    Check '6.2 portable copy started' $ok
    $code = RunWait "$pf\unins000.exe" ($silent + @('/DELETEDATA=1', "/LOG=$res\6-uninstall.log")) 300
    Log "unins000 exit $code"
    $ok = WaitFor { -not (Test-Path "$pf\unins000.exe") } 180
    Check '6.3 uninstaller finished' $ok
    Check '6.4 the portable copy survived the uninstall' (Running "$portable\tray-sing-box.exe")
    Check '6.5 data dir deleted with /DELETEDATA=1' (-not (Test-Path $pd))
    Check '6.6 install dir removed' (-not (Test-Path $pf))
    Check '6.7 task deleted' (-not (TaskInfo))
    SaveLog "$portable\tray-sing-box.log" '6-portable.log'
    $code = RunWait "$portable\tray-sing-box.exe" @('--quit') 60
    Log "portable --quit exit $code"

    WriteSummary
}
catch {
    Log "EXCEPTION: $($_.Exception.Message) at $($_.InvocationInfo.PositionMessage)"
    WriteSummary 'ABORTED by an exception, see trace.txt'
}

if (-not (Test-Path (Join-Path $root 'keep-open'))) {
    & shutdown.exe /s /t 5
}
