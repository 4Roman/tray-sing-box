<#
Runs the installer test (install-test.ps1) in Windows Sandbox: a disposable
Windows where the setup may take over a portable copy, register the autostart
task and write %ProgramData% — none of it touches this machine.

Needs the Windows Sandbox feature (once, elevated PowerShell, then a reboot):
    Enable-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM -All

Usage, from the repository root in an ordinary PowerShell:
    build\installer\sandbox\run.ps1 -SingBoxDir <folder with sing-box.exe>

-SingBoxDir: sing-box.exe (and its DLLs) to put into the portable copy; they
are only copied. The portable copy gets a minimal config.json of its own (a
mixed inbound on 127.0.0.1:2080, direct outbound) — never a real one.
-Setup / -Exe default to what `iscc build\installer\tray-sing-box.iss` and
`make` produce. -KeepOpen leaves the sandbox running after the test.
Exit code 0 when every check passed.
#>
param(
    [Parameter(Mandatory = $true)][string]$SingBoxDir,
    [string]$Setup = (Join-Path $PSScriptRoot '..\..\..\dist\tray-sing-box-0.0.0-setup.exe'),
    [string]$Exe = (Join-Path $PSScriptRoot '..\..\..\bin\tray-sing-box.exe'),
    [string]$StageDir = (Join-Path $env:TEMP ('tray-sing-box-sandbox-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))),
    [int]$TimeoutMinutes = 20,
    [switch]$KeepOpen
)

$ErrorActionPreference = 'Stop'

$sandbox = Join-Path $env:windir 'System32\WindowsSandbox.exe'
if (-not (Test-Path $sandbox)) {
    throw "Windows Sandbox is not enabled. Once, in an elevated PowerShell: Enable-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM -All (then reboot)"
}
foreach ($f in @($Setup, $Exe, (Join-Path $SingBoxDir 'sing-box.exe'))) {
    if (-not (Test-Path $f)) { throw "not found: $f" }
}

$payload = Join-Path $StageDir 'payload'
New-Item -ItemType Directory -Force $payload | Out-Null
Copy-Item -Path $Setup -Destination (Join-Path $StageDir 'setup.exe')
Copy-Item -Path (Join-Path $PSScriptRoot 'install-test.ps1') -Destination $StageDir
Copy-Item -Path $Exe -Destination (Join-Path $payload 'tray-sing-box.exe')
Copy-Item -Path (Join-Path $SingBoxDir 'sing-box.exe') -Destination $payload
Get-ChildItem -Path $SingBoxDir -Filter '*.dll' | Copy-Item -Destination $payload
Set-Content -Path (Join-Path $payload 'config.json') -Encoding ASCII -Value '{"log":{"level":"info","timestamp":true},"inbounds":[{"type":"mixed","tag":"mixed-in","listen":"127.0.0.1","listen_port":2080}],"outbounds":[{"type":"direct","tag":"direct"}]}'
if ($KeepOpen) { New-Item -ItemType File -Path (Join-Path $StageDir 'keep-open') | Out-Null }

$wsb = Join-Path $StageDir 'install-test.wsb'
$hostFolder = [Security.SecurityElement]::Escape((Resolve-Path $StageDir).Path)
@"
<Configuration>
  <MappedFolders>
    <MappedFolder>
      <HostFolder>$hostFolder</HostFolder>
      <SandboxFolder>C:\sbtest</SandboxFolder>
      <ReadOnly>false</ReadOnly>
    </MappedFolder>
  </MappedFolders>
  <LogonCommand>
    <Command>powershell.exe -ExecutionPolicy Bypass -WindowStyle Minimized -File C:\sbtest\install-test.ps1</Command>
  </LogonCommand>
</Configuration>
"@ | Set-Content -Path $wsb -Encoding UTF8

Write-Host "Staged in $StageDir, starting Windows Sandbox..."
Start-Process -FilePath $sandbox -ArgumentList "`"$wsb`""

$summary = Join-Path $StageDir 'results\summary.txt'
$deadline = (Get-Date).AddMinutes($TimeoutMinutes)
while (-not (Test-Path $summary) -and (Get-Date) -lt $deadline) { Start-Sleep -Seconds 5 }
if (-not (Test-Path $summary)) {
    Write-Host "No result after $TimeoutMinutes min; progress: $(Join-Path $StageDir 'results\trace.txt')"
    exit 2
}
Start-Sleep -Seconds 1 # the summary is written in one go, but give it a moment
$text = Get-Content -Path $summary -Encoding UTF8
$text | Write-Host
if ($text[0] -like 'RESULT: ALL PASSED*') { exit 0 }
exit 1
