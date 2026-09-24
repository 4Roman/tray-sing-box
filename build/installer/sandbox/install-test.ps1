# Installer test, run INSIDE Windows Sandbox by run.ps1 (Windows PowerShell
# 5.1 - no pwsh-only syntax, ASCII only: 5.1 reads a BOM-less file as ANSI).
# Everything happens in the disposable sandbox:
#   1. a portable copy with autostart and a running VPN (the user's situation
#      before the installer existed);
#   2. silent install over it: the running copy quits, --migrate takes it
#      over, the task is repointed, the installed copy is relaunched and
#      restores the VPN from Program Files;
#   3. silent upgrade: the running instance quits and is relaunched, sing-box
#      keeps running (same PID);
#   4. silent uninstall: processes, task, registry intent and program files
#      gone, data kept;
#   5. reinstall over the kept data, the task launches the app;
#   6. uninstall with /DELETEDATA=1 while a portable copy runs: the portable
#      copy survives, the data dir is deleted.
# Input: C:\sbtest (read-only mapping). Results: C:\sbresults (summary.txt,
# trace.txt, logs). The sandbox shuts itself down at the end unless
# C:\sbtest\keep-open exists.
param([switch]$Elevated)

$ErrorActionPreference = 'Continue'
$root = 'C:\sbtest'
$res = 'C:\sbresults'

# It repoints the autostart task, rewrites HKCU\Software\SingBoxTray, deletes
# both and shuts the machine down: never anywhere but in the sandbox
if ([Environment]::UserName -ne 'WDAGUtilityAccount' -or -not $PSCommandPath.StartsWith("$root\", [StringComparison]::OrdinalIgnoreCase)) {
    Write-Host 'install-test.ps1 runs only inside Windows Sandbox (started by run.ps1)'
    exit 3
}

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

# First line: "RESULT: ALL PASSED, N checks" (what run.ps1 looks for),
# "RESULT: N FAILED, M checks" or "RESULT: ABORTED (...)"
function WriteSummary([string]$aborted = '') {
    $fail = @($script:checks | Where-Object { -not $_.OK })
    $head = "RESULT: ALL PASSED, $($script:checks.Count) checks"
    if ($fail.Count -gt 0) { $head = "RESULT: $($fail.Count) FAILED, $($script:checks.Count) checks" }
    if ($aborted) { $head = "RESULT: ABORTED ($aborted), $($fail.Count) failed of $($script:checks.Count) checks" }
    $lines = @($head)
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
        WriteSummary 'not elevated'
        exit 1
    }
    Log 'not elevated: relaunching with RunAs (confirm the UAC prompt inside the sandbox)'
    try {
        Start-Process powershell.exe -Verb RunAs -ErrorAction Stop -ArgumentList @('-ExecutionPolicy', 'Bypass', '-File', $PSCommandPath, '-Elevated')
    }
    catch {
        Log "elevation declined: $($_.Exception.Message)"
        WriteSummary 'elevation declined'
        exit 1
    }
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

# Not Start-Process -Wait: it also waits for every child process - the setup
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

# The uninstaller hands over to a copy of itself in TEMP: unins000.exe exits
# (and is deleted) before {app} is removed and before the /DELETEDATA step
function Uninstall([string[]]$extra, [string]$logName) {
    $code = RunWait "$pf\unins000.exe" ($silent + $extra + @("/LOG=$res\$logName")) 300
    $gone = WaitFor { -not (Test-Path "$pf\unins000.exe") } 180
    $cloneDone = WaitFor { @(Get-CimInstance Win32_Process -Filter "Name='_unins.tmp' OR Name LIKE '[_]iu%.tmp'").Count -eq 0 } 120
    return [pscustomobject]@{ Code = $code; Done = ($gone -and $cloneDone) }
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

function TaskIs($t, [string]$exe) {
    return [bool]($t -and $t.Command -ieq $exe -and $t.RunLevel -eq 'HighestAvailable' -and $t.Version -eq '2')
}

function Intent {
    $v = Get-ItemProperty -Path 'HKCU:\Software\SingBoxTray' -Name VPNRunning -ErrorAction SilentlyContinue
    if ($v) { return [int]$v.VPNRunning }
    return $null
}

# The mixed inbound of the test config, owned by the given sing-box.exe
function Listening([string]$exe) {
    $ids = @(Procs $exe | ForEach-Object { [int]$_.ProcessId })
    $conns = @(Get-NetTCPConnection -LocalPort 2080 -State Listen -ErrorAction SilentlyContinue |
        Where-Object { $ids -contains [int]$_.OwningProcess })
    return ($conns.Count -gt 0)
}

function LogText([string]$logPath) {
    if (-not (Test-Path $logPath)) { return '' }
    return [string](Get-Content -Path $logPath -Raw -Encoding UTF8)
}

# The last session of an app log (after the last "Application started")
function LastSession([string]$logPath) {
    $text = LogText $logPath
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
    Check '1.2 task launches the portable exe (HighestAvailable, version 2)' (TaskIs $t "$portable\tray-sing-box.exe") (TaskText $t)

    if (-not (Test-Path 'HKCU:\Software\SingBoxTray')) { New-Item -Path 'HKCU:\Software\SingBoxTray' | Out-Null }
    New-ItemProperty -Path 'HKCU:\Software\SingBoxTray' -Name VPNRunning -PropertyType DWord -Value 1 -Force | Out-Null
    Start-Process -FilePath "$portable\tray-sing-box.exe"
    $ok = WaitFor { Listening "$portable\sing-box.exe" } 60
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
    $ok = WaitFor { (Running "$pf\tray-sing-box.exe") -and (Listening "$pf\sing-box.exe") } 90
    Check '2.8 relaunched installed app restored the VPN from Program Files' $ok
    $t = TaskInfo
    Check '2.9 task repointed at the installed exe' (TaskIs $t "$pf\tray-sing-box.exe") (TaskText $t)
    Check '2.10 intent still 1' ((Intent) -eq 1) "intent $(Intent)"
    Check '2.11 portable folder left intact' ((Test-Path "$portable\config.json") -and (Test-Path "$portable\sing-box.exe") -and (Test-Path "$portable\tray-sing-box.exe"))

    # Owner Administrators; protected DACL of exactly SYSTEM and
    # Administrators (full) and OWNER RIGHTS (READ_CONTROL), nothing inherited
    $sidType = [Security.Principal.SecurityIdentifier]
    $acl = $null
    if (Test-Path $pd) { $acl = Get-Acl -Path $pd }
    if ($acl) {
        $owner = $acl.GetOwner($sidType).Value
        $want = @{ 'S-1-5-18' = 0x1F01FF; 'S-1-5-32-544' = 0x1F01FF; 'S-1-3-4' = 0x20000 }
        $rules = @($acl.GetAccessRules($true, $true, $sidType))
        $bad = @($rules | Where-Object {
                $_.AccessControlType -ne 'Allow' -or $_.IsInherited -or
                -not $want.ContainsKey($_.IdentityReference.Value) -or
                ([int]$_.FileSystemRights -ne $want[$_.IdentityReference.Value]) })
        $aclText = ($rules | ForEach-Object { '{0}:{1:X}' -f $_.IdentityReference.Value, [int]$_.FileSystemRights }) -join ', '
        Check '2.12 data dir: owner Administrators, protected, SYSTEM/Administrators full, OWNER RIGHTS read-control only' ($owner -eq 'S-1-5-32-544' -and $acl.AreAccessRulesProtected -and $rules.Count -eq 3 -and $bad.Count -eq 0) "owner $owner, protected $($acl.AreAccessRulesProtected), rules $aclText"
    }
    else {
        Check '2.12 data dir ACL' $false 'data dir missing'
    }
    & icacls.exe $pd | Out-File -FilePath (Join-Path $res '2-icacls.txt') -Encoding UTF8
    Check '2.13 installed app runs the installed layout' ((LastSession "$pd\tray-sing-box.log") -match 'Layout: installed')
    Check '2.14 the takeover logged the portable folder' ((LogText "$pd\tray-sing-box.log") -match [regex]::Escape("Taking over the previous installation in $portable"))
    SaveLog "$pd\tray-sing-box.log" '2-installed.log'
    SaveLog "$pf\tray-sing-box.log" '2-bin-fallback.log' # only when the data dir was unusable
    SaveLog "$pd\sing-box-console.log" '2-console.log'

    # --- 3. upgrade over the running installed copy --------------------------
    Log '--- 3. silent upgrade'
    $sbPid = FirstPid "$pf\sing-box.exe"
    $trayPid = FirstPid "$pf\tray-sing-box.exe"
    $code = RunWait $setup ($silent + @("/LOG=$res\3-setup.log")) 300
    Check '3.1 setup exits 0' ($code -eq 0) "exit $code"
    $ok = WaitFor { $n = FirstPid "$pf\tray-sing-box.exe"; ($n -ne 0) -and ($n -ne $trayPid) } 90
    Check '3.2 old instance quit, new one started' $ok "before $trayPid, after $(FirstPid "$pf\tray-sing-box.exe")"
    $ok = WaitFor { (LastSession "$pd\tray-sing-box.log") -match 'already running, not starting new instance' } 30
    Check '3.3 new instance adopted the running sing-box' $ok
    Start-Sleep -Seconds 5 # a few monitor ticks: the adopted process must stay the only one
    $sbNow = @(Procs "$pf\sing-box.exe")
    Check '3.4 sing-box kept running through the upgrade (same PID)' ($sbPid -ne 0 -and $sbNow.Count -eq 1 -and [int]$sbNow[0].ProcessId -eq $sbPid) "before $sbPid, after $(($sbNow | ForEach-Object { $_.ProcessId }) -join ',')"
    Check '3.5 VPN still listening' (Listening "$pf\sing-box.exe")
    $t = TaskInfo
    Check '3.6 task still launches the installed exe' (TaskIs $t "$pf\tray-sing-box.exe") (TaskText $t)
    SaveLog "$pd\tray-sing-box.log" '3-installed.log'

    # --- 4. uninstall, data kept ----------------------------------------------
    Log '--- 4. silent uninstall (data kept)'
    $u = Uninstall @() '4-uninstall.log'
    Check '4.1 uninstaller exits 0 and finishes' ($u.Code -eq 0 -and $u.Done) "exit $($u.Code), finished $($u.Done)"
    Check '4.2 no process of the installation left' ((-not (Running "$pf\tray-sing-box.exe")) -and (-not (Running "$pf\sing-box.exe")))
    $left = @(Get-ChildItem -Path $pf -Force -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
    Check '4.3 program files cleaned' ($left.Count -eq 0) ("left: " + ($left -join ', '))
    Check '4.4 task deleted' (-not (TaskInfo))
    Check '4.5 registry intent deleted' (-not (Test-Path 'HKCU:\Software\SingBoxTray'))
    Check '4.6 data kept without /DELETEDATA' (Test-Path "$pd\config.json")
    Check '4.7 portable folder still intact' ((Test-Path "$portable\config.json") -and (Test-Path "$portable\sing-box.exe"))
    # The tray app was asked to quit (graceful), only sing-box was terminated
    Check '4.8 the tray app quit gracefully, only sing-box was terminated' (((LogText "$pd\tray-sing-box.log") -match '--quit: instance asked to exit') -and -not ((LastSession "$pd\tray-sing-box.log") -match 'Stopping tray-sing-box\.exe'))
    SaveLog "$pd\tray-sing-box.log" '4-installed.log'

    # --- 5. reinstall over the kept data, launch through the task -------------
    Log '--- 5. reinstall, start through the task'
    $code = RunWait $setup ($silent + @("/LOG=$res\5-setup.log")) 300
    Check '5.1 setup exits 0' ($code -eq 0) "exit $code"
    Check '5.2 a silent install with nothing running launches nothing' (-not (Running "$pf\tray-sing-box.exe"))
    $t = TaskInfo
    Check '5.3 task registered for the installed exe' (TaskIs $t "$pf\tray-sing-box.exe") (TaskText $t)
    # Expected: the uninstall removed it and there is no takeover source now -
    # the "update sing-box" tray item downloads it (the updater handles a missing binary)
    Log "info: sing-box.exe after reinstall over kept data: $(Test-Path "$pf\sing-box.exe")"
    & schtasks.exe /Run /TN SingBoxTray | Out-Null
    $ok = WaitFor { Running "$pf\tray-sing-box.exe" } 30
    Check '5.4 the task starts the installed app' $ok
    $ok = WaitFor { (LastSession "$pd\tray-sing-box.log") -match 'Restoring VPN state: false' } 30
    Check '5.5 restore reads the deleted intent as off' $ok
    SaveLog "$pd\tray-sing-box.log" '5-installed.log'

    # --- 6. uninstall with /DELETEDATA=1 while a portable copy runs -----------
    Log '--- 6. uninstall with /DELETEDATA=1, a portable copy running'
    $code = RunWait "$pf\tray-sing-box.exe" @('--quit') 90
    Check '6.1 --quit ends the installed instance (exit 0)' ($code -eq 0) "exit $code"
    Start-Process -FilePath "$portable\tray-sing-box.exe"
    # This line comes after the mutex, the installation marker and the quit
    # event exist
    $ok = WaitFor { (Running "$portable\tray-sing-box.exe") -and ((LastSession "$portable\tray-sing-box.log") -match 'Restoring VPN state') } 30
    Check '6.2 portable copy started' $ok
    $u = Uninstall @('/DELETEDATA=1') '6-uninstall.log'
    Check '6.3 uninstaller exits 0 and finishes' ($u.Code -eq 0 -and $u.Done) "exit $($u.Code), finished $($u.Done)"
    Check '6.4 the portable copy survived the uninstall' (Running "$portable\tray-sing-box.exe")
    Check '6.5 data dir deleted with /DELETEDATA=1' (-not (Test-Path $pd))
    Check '6.6 install dir removed' (-not (Test-Path $pf))
    Check '6.7 task deleted' (-not (TaskInfo))
    SaveLog "$portable\tray-sing-box.log" '6-portable.log'
    $code = RunWait "$portable\tray-sing-box.exe" @('--quit') 90
    Log "portable --quit exit $code"

    WriteSummary
}
catch {
    Log "EXCEPTION: $($_.Exception.Message) at $($_.InvocationInfo.PositionMessage)"
    WriteSummary 'exception, see trace.txt'
}

if (-not (Test-Path (Join-Path $root 'keep-open'))) {
    & shutdown.exe /s /t 5
}
