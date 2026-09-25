<#
Life-cycle test of an installed copy in Windows Sandbox: the checks that
otherwise need a real machine and a reboot (sing-box crash, explorer restart,
start/stop from the tray, reboot with the VPN off and on, quit) - driven
through the Windows Sandbox command line (wsb, Windows 11 24H2 and later),
which can run commands in a running sandbox and survives a restart inside it.
lifecycle-test.ps1 runs each phase inside; nothing runs on this machine but
the sandbox.

Usage, from the repository root in PowerShell 7:
    build\installer\sandbox\lifecycle.ps1 -Setup <setup.exe> -SingBoxDir <folder with sing-box.exe>

-Phases: the default is the whole life cycle; "reboot" restarts the sandbox
between phases. The update scenario needs an OLDER published release's setup
and the network (it updates from the real GitHub release):
    lifecycle.ps1 -Setup <setup of v1.0.0> -SingBoxDir <dir> -Network -ExpectVersion v1.0.1 -Phases install,update,collect
-Uac turns User Account Control on first (the sandbox has it off: every
process runs elevated, so nothing that depends on the shell running BELOW the
app is exercised - the explorer restart broadcast, the browser the settings
page opens in, the setup started by the shell); elevation is then granted
without a prompt, and each phase elevates itself:
    lifecycle.ps1 -Setup <setup.exe> -SingBoxDir <dir> -Uac -Phases dir-refused,interactive,...
-KeepOpen leaves the sandbox running (its id is printed; `wsb stop --id <id>`).
For a look by hand at a clean installation (the first-config section of the
settings page), with the network and the clipboard shared:
    lifecycle.ps1 -Setup <setup.exe> -SingBoxDir <dir> -Phases fresh -Network -Clipboard -KeepOpen
Exit code 0 when every phase passed.
#>
param(
    [Parameter(Mandatory = $true)][string]$Setup,
    [Parameter(Mandatory = $true)][string]$SingBoxDir,
    [string[]]$Phases = @('install', 'crash', 'explorer', 'stop', 'reboot', 'boot-off', 'reboot', 'boot-on', 'cancel', 'giveup', 'quit', 'collect'),
    [string]$ExpectVersion = '',
    [switch]$Network,
    [switch]$Clipboard,
    [switch]$Uac,
    [string]$StageDir = (Join-Path $env:TEMP ('tray-sing-box-lifecycle-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))),
    [int]$PhaseTimeoutMinutes = 15,
    [switch]$KeepOpen
)

$ErrorActionPreference = 'Stop'
# pwsh -File passes "a,b,c" as one string
$Phases = @($Phases | ForEach-Object { $_ -split ',' } | Where-Object { $_ })

$wsbExe = (Get-Command wsb.exe -ErrorAction SilentlyContinue).Source
if (-not $wsbExe) { throw 'wsb.exe (the Windows Sandbox command line) not found: Windows 11 24H2 or later with the Windows Sandbox feature is needed' }
foreach ($f in @($Setup, (Join-Path $SingBoxDir 'sing-box.exe'))) {
    if (-not (Test-Path $f)) { throw "not found: $f" }
}

$inputDir = Join-Path $StageDir 'input'
$resultsDir = Join-Path $StageDir 'results'
$payload = Join-Path $inputDir 'payload'
New-Item -ItemType Directory -Force $payload, $resultsDir | Out-Null
Copy-Item -Path $Setup -Destination (Join-Path $inputDir 'setup.exe')
Copy-Item -Path (Join-Path $PSScriptRoot 'lifecycle-test.ps1') -Destination $inputDir
Copy-Item -Path (Join-Path $SingBoxDir 'sing-box.exe') -Destination $payload
Get-ChildItem -Path $SingBoxDir -Filter '*.dll' | Copy-Item -Destination $payload
Set-Content -Path (Join-Path $payload 'config.json') -Encoding ASCII -Value '{"log":{"level":"info","timestamp":true},"inbounds":[{"type":"mixed","tag":"mixed-in","listen":"127.0.0.1","listen_port":2080}],"outbounds":[{"type":"direct","tag":"direct"}]}'
# For the settings page (phase web): a config the guard must refuse, and one
# with a credential the page must never show (a documentation-only address)
Set-Content -Path (Join-Path $payload 'web-risky.json') -Encoding ASCII -Value '{"log":{"level":"info"},"inbounds":[{"type":"mixed","tag":"mixed-in","listen":"127.0.0.1","listen_port":2080}],"outbounds":[{"type":"direct","tag":"direct"}],"experimental":{"clash_api":{"external_controller":"0.0.0.0:9090"}}}'
Set-Content -Path (Join-Path $payload 'web-config.json') -Encoding ASCII -Value '{"log":{"level":"info","timestamp":true},"inbounds":[{"type":"mixed","tag":"mixed-in","listen":"127.0.0.1","listen_port":2080}],"outbounds":[{"type":"direct","tag":"direct"},{"type":"vless","tag":"test-vless","server":"192.0.2.1","server_port":443,"uuid":"11111111-2222-3333-4444-555555555555","tls":{"enabled":true,"server_name":"example.com"}}],"route":{"final":"direct"}}'

$net = if ($Network) { 'Enable' } else { 'Disable' }
$clip = if ($Clipboard) { 'Enable' } else { 'Disable' }
$inputHost = [Security.SecurityElement]::Escape((Resolve-Path $inputDir).Path)
$resultsHost = [Security.SecurityElement]::Escape((Resolve-Path $resultsDir).Path)
$config = @"
<Configuration>
  <Networking>$net</Networking>
  <ClipboardRedirection>$clip</ClipboardRedirection>
  <AudioInput>Disable</AudioInput>
  <VideoInput>Disable</VideoInput>
  <MappedFolders>
    <MappedFolder>
      <HostFolder>$inputHost</HostFolder>
      <SandboxFolder>C:\sbtest</SandboxFolder>
      <ReadOnly>true</ReadOnly>
    </MappedFolder>
    <MappedFolder>
      <HostFolder>$resultsHost</HostFolder>
      <SandboxFolder>C:\sbresults</SandboxFolder>
      <ReadOnly>false</ReadOnly>
    </MappedFolder>
  </MappedFolders>
</Configuration>
"@

function Wsb([string[]]$argList) {
    $out = & $wsbExe @argList --raw 2>&1 | Out-String
    try { return ($out | ConvertFrom-Json) } catch { return [pscustomobject]@{ Error = $out.Trim() } }
}

# A command in the user's session; $null while there is none (the sandbox is
# still booting or restarting)
function UserExec([string]$command) {
    $r = Wsb @('exec', '--id', $script:id, '-r', 'ExistingLogin', '-c', $command)
    if ($null -ne $r.ExitCode) { return [int]$r.ExitCode }
    return $null
}

function BootTime {
    $f = Join-Path $resultsDir 'boot.txt'
    Remove-Item -LiteralPath $f -ErrorAction SilentlyContinue
    $code = UserExec 'powershell.exe -NoProfile -Command "(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToString(''o'') | Out-File C:\sbresults\boot.txt -Encoding ascii"'
    if ($code -ne 0 -or -not (Test-Path $f)) { return $null }
    return (Get-Content $f -Raw).Trim()
}

# Returns the boot time of a sandbox with a logged-on user; a different one
# than $notBoot after a restart
function WaitForUser([int]$seconds, [string]$notBoot = '') {
    $deadline = (Get-Date).AddSeconds($seconds)
    while ((Get-Date) -lt $deadline) {
        $b = BootTime
        if ($b -and $b -ne $notBoot) { return $b }
        Start-Sleep -Seconds 3
    }
    throw "no user session in the sandbox within $seconds s"
}

function Say([string]$m, [string]$color = 'White') { Write-Host ('{0:HH:mm:ss} {1}' -f (Get-Date), $m) -ForegroundColor $color }

$r = Wsb @('start', '-c', $config)
if (-not $r.Id) { throw "wsb start failed: $($r.Error)" }
$script:id = $r.Id
Say "Sandbox $id, staged in $StageDir"
$failed = 0
try {
    # The window logs the user on (and shows what happens)
    Start-Process -FilePath $wsbExe -ArgumentList @('connect', '--id', $id)
    $boot = WaitForUser 300
    if ($Uac) {
        Say '== UAC on (elevation without a prompt), reboot'
        $key = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
        $set = "cmd.exe /c reg add $key /v EnableLUA /t REG_DWORD /d 1 /f & reg add $key /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 0 /f & reg add $key /v PromptOnSecureDesktop /t REG_DWORD /d 0 /f"
        $r = Wsb @('exec', '--id', $id, '-r', 'System', '-c', $set)
        if ($r.ExitCode -ne 0) { throw "turning UAC on failed: $($r.Error)$($r.ExitCode)" }
        [void](Wsb @('exec', '--id', $id, '-r', 'System', '-c', 'shutdown.exe /r /t 0'))
        $boot = WaitForUser 600 $boot
        Say "   up again, boot $boot"
    }
    foreach ($phase in $Phases) {
        if ($phase -eq 'reboot') {
            Say '== reboot'
            [void](Wsb @('exec', '--id', $id, '-r', 'System', '-c', 'shutdown.exe /r /t 0'))
            $boot = WaitForUser 600 $boot
            Say "   up again, boot $boot"
            continue
        }
        Say "== $phase"
        $file = Join-Path $resultsDir "$phase.txt"
        Remove-Item -LiteralPath $file -ErrorAction SilentlyContinue
        $cmd = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\sbtest\lifecycle-test.ps1 -Phase $phase"
        if ($ExpectVersion) { $cmd += " -ExpectVersion $ExpectVersion" }
        $job = Start-ThreadJob -ScriptBlock { param($exe, $id, $c) & $exe exec --id $id -r ExistingLogin -c $c --raw 2>&1 | Out-String } -ArgumentList $wsbExe, $id, $cmd
        $deadline = (Get-Date).AddMinutes($PhaseTimeoutMinutes)
        while (-not (Test-Path $file) -and (Get-Date) -lt $deadline) { Start-Sleep -Seconds 2 }
        [void](Wait-Job $job -Timeout 30)
        Remove-Job $job -Force
        if (-not (Test-Path $file)) {
            Say "   no result within $PhaseTimeoutMinutes min" 'Red'
            $failed++
            break
        }
        Start-Sleep -Milliseconds 500
        $text = @(Get-Content -Path $file -Encoding UTF8)
        $color = if ($text[0] -match '^RESULT: ALL PASSED') { 'Green' } else { 'Red' }
        $text | ForEach-Object { Write-Host "   $_" -ForegroundColor $color }
        if ($color -eq 'Red') { $failed++ }
    }
}
finally {
    if ($KeepOpen) {
        Write-Host "Sandbox left running: wsb stop --id $id"
    }
    else {
        [void](Wsb @('stop', '--id', $id))
    }
    Write-Host "Results: $resultsDir"
}
if ($failed -gt 0) { exit 1 }
exit 0
