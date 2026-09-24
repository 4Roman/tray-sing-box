<#
Finishes a release that .github/workflows/release.yml drafted - the
maintainer's side, with the OFFLINE signing key:

    build\release\finish-release.ps1 -Tag v1.2.3 -KeyFile <private key file> [-SingBoxDir <dir>] [-Publish]

1. Downloads the draft's exe.
2. Rebuilds the exe from the tag in a plain clone with the CI's settings (the
   go.mod toolchain, CGO_ENABLED=1, -trimpath, go-winres v0.3.3 - keep in
   sync with release.yml) and requires the SAME SHA-256 as the draft's exe.
   The build is reproducible; signing a CI build blindly would hand the
   maintainer's signature to whoever tampered with CI or with an action it
   runs.
3. Builds the installer here from that verified exe with Inno Setup 6.7.3 (the
   version release.yml pins; Inno Setup output is not reproducible, so the
   draft's setup is replaced rather than compared).
4. With -SingBoxDir: runs the installer test in Windows Sandbox on the final
   files (build\installer\sandbox\run.ps1).
5. Signs checksums.txt with tools/relsign (-key-file: the key never appears on
   a command line) and uploads it with the signature and the setup.
6. With -Publish: publishes the draft; otherwise prints the command.

Needs: gh (logged in), git, go, Inno Setup 6.7.3. Work dir: %TEMP%\tsb-<tag>.
#>
param(
    [Parameter(Mandatory = $true)][ValidatePattern('^v\d+\.\d+\.\d+$')][string]$Tag,
    [Parameter(Mandatory = $true)][string]$KeyFile,
    [string]$SingBoxDir,
    [switch]$Publish
)

$ErrorActionPreference = 'Stop'
function Step([string]$m) { Write-Host "== $m" -ForegroundColor Cyan }
function Native([string]$what) { if ($LASTEXITCODE -ne 0) { throw "$what failed (exit $LASTEXITCODE)" } }

$gh = (Get-Command gh -ErrorAction SilentlyContinue).Source
if (-not $gh) { $gh = Join-Path $env:ProgramFiles 'GitHub CLI\gh.exe' }
if (-not (Test-Path $gh)) { throw 'GitHub CLI (gh) not found' }
if (-not (Test-Path $KeyFile)) { throw "key file not found: $KeyFile" }
$KeyFile = (Resolve-Path $KeyFile).Path
$plain = $Tag.TrimStart('v')
$source = (git -C $PSScriptRoot rev-parse --show-toplevel).Trim()
Native 'git rev-parse'

# Short path: git objects under a long one exceed MAX_PATH
$work = Join-Path $env:TEMP "tsb-$Tag"
if (Test-Path $work) { throw "$work exists (a previous run?) - remove it first" }
$clone = Join-Path $work 'src'
$draft = Join-Path $work 'draft'
$final = Join-Path $work 'final'
New-Item -ItemType Directory -Force $draft, $final | Out-Null

Step "clone $Tag"
# A plain clone, as on CI: Go does not stamp VCS info in a linked worktree
git -c advice.detachedHead=false clone --quiet --no-hardlinks --branch $Tag $source $clone
Native 'git clone'
$cfg = Get-Content (Join-Path $clone 'internal\config\config.go') -Raw
if ($cfg -notmatch 'AppUpdateRepo\s*=\s*"([^"]+)"') { throw 'config.AppUpdateRepo is empty at this tag' }
$repo = $Matches[1]

Step "draft of $repo $Tag"
$state = & $gh release view $Tag -R $repo --json isDraft --jq .isDraft
Native 'gh release view'
if ($state -ne 'true') { throw "$Tag is not a draft on $repo - a published release is not modified" }
$exeName = "tray-sing-box-$plain-windows-amd64.exe"
& $gh release download $Tag -R $repo --dir $draft --pattern $exeName
Native 'gh release download'
$draftExe = Join-Path $draft $exeName

Step 'rebuild the exe from the tag'
$modText = Get-Content (Join-Path $clone 'go.mod') -Raw
$toolchain = if ($modText -match '(?m)^toolchain\s+(go\S+)') { $Matches[1] } elseif ($modText -match '(?m)^go\s+(\S+)') { "go$($Matches[1])" } else { throw 'go.mod names no Go version' }
Push-Location $clone
$savedToolchain, $savedCgo = $env:GOTOOLCHAIN, $env:CGO_ENABLED
try {
    $env:GOTOOLCHAIN = $toolchain
    $env:CGO_ENABLED = '1'
    go version; Native 'go'
    go run ./tools/genicons | Out-Null; Native 'genicons'
    go build -trimpath -ldflags="-H windowsgui -X tray-sing-box/internal/config.Version=$Tag" -o bin/tray-sing-box.exe .; Native 'go build'
    go run github.com/tc-hib/go-winres@v0.3.3 patch --in build/winres/winres.json --no-backup bin/tray-sing-box.exe; Native 'go-winres'
}
finally {
    $env:GOTOOLCHAIN, $env:CGO_ENABLED = $savedToolchain, $savedCgo
    Pop-Location
}
$localExe = Join-Path $clone 'bin\tray-sing-box.exe'
$want = (Get-FileHash $localExe -Algorithm SHA256).Hash
$got = (Get-FileHash $draftExe -Algorithm SHA256).Hash
Write-Host "local build: $want"
Write-Host "draft exe  : $got"
if ($want -ne $got) {
    throw "the draft's exe is NOT what the tag builds to - do not sign it. Compare 'go version -m' of both files (Go version, CGO_ENABLED, vcs.revision) before suspecting CI."
}
Copy-Item $draftExe (Join-Path $final $exeName)

Step 'installer from the verified exe (Inno Setup 6.7.3)'
$entry = @('HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall', 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall', 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall') |
    ForEach-Object { Get-ItemProperty (Join-Path $_ 'Inno Setup 6_is1') -ErrorAction SilentlyContinue } | Select-Object -First 1
if (-not $entry -or $entry.DisplayVersion -ne '6.7.3') { throw "Inno Setup 6.7.3 needed (found '$($entry.DisplayVersion)'): winget install JRSoftware.InnoSetup --version 6.7.3" }
$iscc = Join-Path $entry.InstallLocation 'ISCC.exe'
& $iscc /Q "/DVersion=$plain" "/DSource=$(Join-Path $final $exeName)" "/O$final" (Join-Path $clone 'build\installer\tray-sing-box.iss')
Native 'ISCC'
$setupName = "tray-sing-box-$plain-setup.exe"
if (-not (Test-Path (Join-Path $final $setupName))) { throw "ISCC produced no $setupName" }

if ($SingBoxDir) {
    Step 'installer test in Windows Sandbox'
    & (Join-Path $clone 'build\installer\sandbox\run.ps1') -SingBoxDir $SingBoxDir -Setup (Join-Path $final $setupName) -Exe (Join-Path $final $exeName) -StageDir (Join-Path $work 'sandbox')
    if ($LASTEXITCODE -ne 0) { throw "the installer test did not pass (exit $LASTEXITCODE) - nothing was signed or uploaded" }
}

Step 'sign'
Push-Location $clone
try {
    go run ./tools/relsign -dir $final -key-file $KeyFile; Native 'relsign'
}
finally { Pop-Location }

Step 'upload to the draft'
& $gh release upload $Tag -R $repo --clobber (Join-Path $final $setupName) (Join-Path $final 'checksums.txt') (Join-Path $final 'checksums.txt.sig')
Native 'gh release upload'

if ($Publish) {
    Step 'publish'
    & $gh release edit $Tag -R $repo --draft=false --latest
    Native 'gh release edit'
}
else {
    Write-Host "Draft ready. Publish with:  gh release edit $Tag -R $repo --draft=false --latest"
}
Write-Host "Work dir (safe to delete): $work"
