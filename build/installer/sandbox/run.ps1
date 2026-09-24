<#
Runs the installer test (install-test.ps1) in Windows Sandbox: a disposable
Windows where the setup may take over a portable copy, register the autostart
task and write %ProgramData% - none of it touches this machine. The sandbox
gets no network (the test only needs loopback) and sees the staged inputs
read-only; only its results folder is writable.

Needs the Windows Sandbox feature (once, elevated PowerShell, then a reboot):
    Enable-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM -All

Usage, from the repository root in an ordinary PowerShell:
    build\installer\sandbox\run.ps1 -SingBoxDir <folder with sing-box.exe>

-SingBoxDir: sing-box.exe (and its DLLs) to put into the portable copy; they
are only copied. The portable copy gets a minimal config.json of its own (a
mixed inbound on 127.0.0.1:2080, direct outbound) - never a real one.
-Setup / -Exe default to what `iscc build\installer\tray-sing-box.iss` and
`make` produce. -KeepOpen leaves the sandbox running after the test.
Exit code 0 when every check passed, 1 when not, 2 when there is no result.
#>
param(
    [Parameter(Mandatory = $true)][string]$SingBoxDir,
    [string]$Setup = (Join-Path $PSScriptRoot '..\..\..\dist\tray-sing-box-0.0.0-setup.exe'),
    [string]$Exe = (Join-Path $PSScriptRoot '..\..\..\bin\tray-sing-box.exe'),
    [string]$StageDir = (Join-Path $env:TEMP ('tray-sing-box-sandbox-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))),
    [int]$TimeoutMinutes = 45,
    [switch]$KeepOpen
)

$ErrorActionPreference = 'Stop'

foreach ($f in @($Setup, $Exe, (Join-Path $SingBoxDir 'sing-box.exe'))) {
    if (-not (Test-Path $f)) { throw "not found: $f" }
}

# The launcher: System32 before Windows 11 24H2, an app (with an execution
# alias) since; otherwise the .wsb file association
$launcher = $null
foreach ($name in @('WindowsSandbox.exe', 'wsb.exe')) {
    $cmd = Get-Command $name -ErrorAction SilentlyContinue
    if ($cmd) { $launcher = $cmd.Source; break }
}
if (-not $launcher -and (Test-Path (Join-Path $env:windir 'System32\WindowsSandbox.exe'))) {
    $launcher = Join-Path $env:windir 'System32\WindowsSandbox.exe'
}
$associated = $false
try { $associated = [bool](Get-Item 'Registry::HKEY_CLASSES_ROOT\.wsb' -ErrorAction Stop) } catch { }
if (-not $launcher -and -not $associated) {
    throw "Windows Sandbox is not enabled. Once, in an elevated PowerShell: Enable-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM -All (then reboot)"
}

$inputDir = Join-Path $StageDir 'input'
$resultsDir = Join-Path $StageDir 'results'
$payload = Join-Path $inputDir 'payload'
New-Item -ItemType Directory -Force $payload, $resultsDir | Out-Null
Copy-Item -Path $Setup -Destination (Join-Path $inputDir 'setup.exe')
Copy-Item -Path (Join-Path $PSScriptRoot 'install-test.ps1') -Destination $inputDir
Copy-Item -Path $Exe -Destination (Join-Path $payload 'tray-sing-box.exe')
Copy-Item -Path (Join-Path $SingBoxDir 'sing-box.exe') -Destination $payload
Get-ChildItem -Path $SingBoxDir -Filter '*.dll' | Copy-Item -Destination $payload
Set-Content -Path (Join-Path $payload 'config.json') -Encoding ASCII -Value '{"log":{"level":"info","timestamp":true},"inbounds":[{"type":"mixed","tag":"mixed-in","listen":"127.0.0.1","listen_port":2080}],"outbounds":[{"type":"direct","tag":"direct"}]}'
if ($KeepOpen) { New-Item -ItemType File -Path (Join-Path $inputDir 'keep-open') | Out-Null }

$wsb = Join-Path $StageDir 'install-test.wsb'
$inputHost = [Security.SecurityElement]::Escape((Resolve-Path $inputDir).Path)
$resultsHost = [Security.SecurityElement]::Escape((Resolve-Path $resultsDir).Path)
@"
<Configuration>
  <Networking>Disable</Networking>
  <ClipboardRedirection>Disable</ClipboardRedirection>
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
  <LogonCommand>
    <Command>powershell.exe -ExecutionPolicy Bypass -WindowStyle Minimized -File C:\sbtest\install-test.ps1</Command>
  </LogonCommand>
</Configuration>
"@ | Set-Content -Path $wsb -Encoding UTF8

Write-Host "Staged in $StageDir, starting Windows Sandbox..."
if ($launcher) {
    Start-Process -FilePath $launcher -ArgumentList "`"$wsb`""
}
else {
    Start-Process -FilePath $wsb
}

$summary = Join-Path $resultsDir 'summary.txt'
$trace = Join-Path $resultsDir 'trace.txt'
$started = Get-Date
$deadline = $started.AddMinutes($TimeoutMinutes)
while (-not (Test-Path $summary) -and (Get-Date) -lt $deadline) {
    if (-not (Test-Path $trace) -and ((Get-Date) - $started).TotalMinutes -gt 5) {
        Write-Host "The test did not start within 5 min (no $trace): did the sandbox open and run its logon command?"
        exit 2
    }
    Start-Sleep -Seconds 5
}
if (-not (Test-Path $summary)) {
    Write-Host "No result after $TimeoutMinutes min; progress: $trace"
    exit 2
}
Start-Sleep -Seconds 1 # the summary is written in one go, but give it a moment
$text = @(Get-Content -Path $summary -Encoding UTF8)
$text | Write-Host
if ($text[0] -match '^RESULT: ALL PASSED, \d+ checks$') { exit 0 }
exit 1
