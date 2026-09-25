# Life-cycle test of an installed copy, run INSIDE Windows Sandbox, one phase
# per call, by lifecycle.ps1 (Windows PowerShell 5.1 - no pwsh-only syntax,
# ASCII only: 5.1 reads a BOM-less file as ANSI). The phases are the manual
# checks after a deployment, on a disposable Windows:
#   install   silent install, sing-box + a test config put in place, the task
#             launches the app, the VPN intent "running" is restored
#   dir-refused  a silent install into a folder outside Program Files is
#             refused (such folders are usually user-writable)
#   interactive  the setup started by the shell (with UAC: a normal token it
#             elevates), the wizard clicked through with its defaults, the
#             app launched from the last page
#   fresh     silent install on a clean machine, nothing else: the first-run
#             state for the first-config section of the settings page
#   web       (after fresh, networked sandbox) the settings page in Edge,
#             opened from the tray: login code out of the address bar,
#             sing-box downloaded from the page, a risky config refused, the
#             first config saved, credentials masked, VPN on from the page,
#             a section save, the active server, a history rollback, a
#             subscription from a local provider, the logs, a reload without
#             a session, a second login from the tray
#   crash     sing-box dies -> the monitor restarts it, the death is an ERROR
#   explorer  explorer.exe restarts -> the tray icon comes back
#   stop      the tray toggle (VPN off) -> sing-box stops, intent 0, and a
#             requested stop is not logged as an error
#   boot-off  after a reboot with the VPN off: the task starts the app, the
#             VPN stays off; then the tray toggle turns it on
#   boot-on   after a reboot with the VPN on: restored at logon
#   singbox-update  (networked, after install) the tray item replaces the
#             running older sing-box with the latest release
#   cancel    sing-box cannot start, the tray toggle calls the attempts off
#   giveup    sing-box cannot start (config.json hidden) -> "starting", 5
#             attempts, then the yes/no report; "yes" records the VPN off
#   update    (networked sandbox, an older release installed) the daily check
#             offers -ExpectVersion, both questions answered "yes": the app is
#             replaced and relaunched, sing-box keeps running (same PID)
#   quit      the tray quit item -> the app exits, sing-box keeps running
#   collect   copies the app's logs into the results
# Input: C:\sbtest (read-only). Results: C:\sbresults\<phase>.txt (first
# line "RESULT: ..."), trace.txt, logs\. Exit code 0 = every check passed.
# With UAC on (lifecycle.ps1 -Uac) the phases also check that the shell and the
# browser run below the elevated app - the case the UAC-less sandbox misses.
param(
    [Parameter(Mandatory = $true)][string]$Phase,
    [string]$ExpectVersion = '',
    [switch]$Elevated
)

$ErrorActionPreference = 'Continue'
$root = 'C:\sbtest'
$res = 'C:\sbresults'

# It installs software, rewrites HKCU\Software\SingBoxTray, ends processes and
# restarts explorer: never anywhere but in the sandbox
if ([Environment]::UserName -ne 'WDAGUtilityAccount' -or -not $PSCommandPath.StartsWith("$root\", [StringComparison]::OrdinalIgnoreCase)) {
    Write-Host 'lifecycle-test.ps1 runs only inside Windows Sandbox (started by lifecycle.ps1)'
    exit 3
}

New-Item -ItemType Directory -Force $res | Out-Null
$trace = Join-Path $res 'trace.txt'

function Log([string]$m) {
    Add-Content -Path $trace -Encoding UTF8 -Value ('{0:HH:mm:ss} [{1}] {2}' -f (Get-Date), $Phase, $m)
}

$script:checks = New-Object System.Collections.ArrayList
function Check([string]$name, [bool]$ok, [string]$detail = '') {
    [void]$script:checks.Add([pscustomobject]@{ Name = $name; OK = $ok; Detail = $detail })
    $mark = 'FAIL'
    if ($ok) { $mark = 'PASS' }
    Log "$mark $name  $detail"
}

function Finish([string]$aborted = '') {
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
    $lines | Out-File -FilePath (Join-Path $res "$Phase.txt") -Encoding UTF8
    if ($aborted -or $fail.Count -gt 0) { exit 1 }
    exit 0
}

# An unexpected terminating error still leaves a result
trap {
    Log "error: $($_.Exception.Message) at line $($_.InvocationInfo.ScriptLineNumber)"
    Finish "error: $($_.Exception.Message)"
}

# With UAC on (lifecycle.ps1 -Uac) the command arrives with the user's normal
# token: the phase relaunches itself elevated (the sandbox then elevates
# without asking); the host waits for the result file either way
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    if ($Elevated) {
        Log 'still not elevated after RunAs'
        Finish 'not elevated'
    }
    $again = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $PSCommandPath, '-Phase', $Phase, '-Elevated')
    if ($ExpectVersion) { $again += @('-ExpectVersion', $ExpectVersion) }
    try {
        Start-Process -FilePath powershell.exe -Verb RunAs -ArgumentList $again -ErrorAction Stop
    }
    catch {
        Log "elevation failed: $($_.Exception.Message)"
        Finish 'elevation failed'
    }
    exit 0
}

# --- Win32: the tray window, its icon, message boxes ------------------------

Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

public static class SbWin {
    delegate bool EnumProc(IntPtr hwnd, IntPtr param);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    static extern IntPtr FindWindowEx(IntPtr parent, IntPtr after, string cls, string title);
    [DllImport("user32.dll")]
    static extern uint GetWindowThreadProcessId(IntPtr hwnd, out uint pid);
    [DllImport("user32.dll")]
    static extern bool PostMessage(IntPtr hwnd, uint msg, IntPtr wParam, IntPtr lParam);
    [DllImport("user32.dll")]
    static extern bool EnumWindows(EnumProc f, IntPtr param);
    [DllImport("user32.dll")]
    static extern bool EnumChildWindows(IntPtr parent, EnumProc f, IntPtr param);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    static extern int GetClassName(IntPtr hwnd, StringBuilder sb, int max);
    [DllImport("user32.dll")]
    static extern bool IsWindowVisible(IntPtr hwnd);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    static extern IntPtr SendMessageTimeout(IntPtr hwnd, uint msg, IntPtr wParam, StringBuilder lParam, uint flags, uint timeout, out IntPtr result);

    [StructLayout(LayoutKind.Sequential)]
    struct NotifyIconId { public uint cbSize; public IntPtr hWnd; public uint uID; public Guid guidItem; }
    [StructLayout(LayoutKind.Sequential)]
    struct Rect { public int left, top, right, bottom; }
    [DllImport("shell32.dll")]
    static extern int Shell_NotifyIconGetRect(ref NotifyIconId id, out Rect rect);

    static string ClassOf(IntPtr hwnd) {
        StringBuilder sb = new StringBuilder(256);
        GetClassName(hwnd, sb, sb.Capacity);
        return sb.ToString();
    }

    static uint PidOf(IntPtr hwnd) {
        uint pid;
        GetWindowThreadProcessId(hwnd, out pid);
        return pid;
    }

    // The hidden window systray creates for the process (class SystrayClass)
    public static IntPtr TrayWindow(uint pid) {
        IntPtr h = IntPtr.Zero;
        while ((h = FindWindowEx(IntPtr.Zero, h, "SystrayClass", null)) != IntPtr.Zero) {
            if (PidOf(h) == pid) return h;
        }
        return IntPtr.Zero;
    }

    public static bool ShellReady() {
        return FindWindowEx(IntPtr.Zero, IntPtr.Zero, "Shell_TrayWnd", null) != IntPtr.Zero;
    }

    // S_OK (0) while the shell has the icon (systray registers it as ID 100)
    public static int IconState(IntPtr trayWindow, uint iconId) {
        NotifyIconId id = new NotifyIconId();
        id.cbSize = (uint)Marshal.SizeOf(typeof(NotifyIconId));
        id.hWnd = trayWindow;
        id.uID = iconId;
        Rect r;
        return Shell_NotifyIconGetRect(ref id, out r);
    }

    // A menu click, as the popup menu reports it
    public static bool Command(IntPtr hwnd, int id) {
        return PostMessage(hwnd, 0x0111, new IntPtr(id), IntPtr.Zero);
    }

    // Visible message boxes (dialog class #32770) of a process
    public static IntPtr[] Dialogs(uint pid) {
        List<IntPtr> found = new List<IntPtr>();
        EnumWindows(delegate (IntPtr h, IntPtr p) {
            if (IsWindowVisible(h) && PidOf(h) == pid && ClassOf(h) == "#32770") found.Add(h);
            return true;
        }, IntPtr.Zero);
        return found.ToArray();
    }

    static string TextOf(IntPtr hwnd) {
        StringBuilder sb = new StringBuilder(8192);
        IntPtr result;
        // WM_GETTEXT; GetWindowText does not read controls of another process
        SendMessageTimeout(hwnd, 0x000D, new IntPtr(sb.Capacity), sb, 0x0002, 2000, out result);
        return sb.ToString();
    }

    public static string DialogText(IntPtr dialog) {
        StringBuilder all = new StringBuilder(TextOf(dialog));
        EnumChildWindows(dialog, delegate (IntPtr h, IntPtr p) {
            if (ClassOf(h) == "Static") {
                string t = TextOf(h);
                if (t.Length > 0) all.Append(" | ").Append(t);
            }
            return true;
        }, IntPtr.Zero);
        return all.ToString();
    }

    // IDYES through the dialog's WM_COMMAND, as a click on the button sends it
    public static bool AnswerYes(IntPtr dialog) {
        return PostMessage(dialog, 0x0111, new IntPtr(6), IntPtr.Zero);
    }

    [DllImport("user32.dll")]
    static extern IntPtr GetDlgItem(IntPtr dialog, int id);

    // Closes an OK box: a click on its OK button (IDOK), WM_CLOSE without one
    public static bool CloseBox(IntPtr dialog) {
        IntPtr ok = GetDlgItem(dialog, 1);
        if (ok == IntPtr.Zero) ok = GetDlgItem(dialog, 2);
        if (ok != IntPtr.Zero) return PostMessage(ok, 0x00F5, IntPtr.Zero, IntPtr.Zero); // BM_CLICK
        return PostMessage(dialog, 0x0010, IntPtr.Zero, IntPtr.Zero); // WM_CLOSE
    }

    public static bool Exists(IntPtr hwnd) { return IsWindowVisible(hwnd); }

    // --- integrity level of a process (0x2000 medium, 0x3000 high) ---
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
    [DllImport("kernel32.dll")]
    static extern bool CloseHandle(IntPtr h);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool GetTokenInformation(IntPtr token, int cls, IntPtr buf, int len, out int ret);
    [DllImport("advapi32.dll")]
    static extern IntPtr GetSidSubAuthority(IntPtr sid, uint n);
    [DllImport("advapi32.dll")]
    static extern IntPtr GetSidSubAuthorityCount(IntPtr sid);

    public static int Level(int pid) {
        IntPtr p = OpenProcess(0x1000, false, pid); // PROCESS_QUERY_LIMITED_INFORMATION
        if (p == IntPtr.Zero) return -1;
        IntPtr t;
        bool ok = OpenProcessToken(p, 0x8, out t); // TOKEN_QUERY
        CloseHandle(p);
        if (!ok) return -1;
        int n;
        GetTokenInformation(t, 25, IntPtr.Zero, 0, out n); // TokenIntegrityLevel
        IntPtr b = Marshal.AllocHGlobal(n);
        try {
            if (!GetTokenInformation(t, 25, b, n, out n)) return -1;
            IntPtr sid = Marshal.ReadIntPtr(b);
            int count = Marshal.ReadByte(GetSidSubAuthorityCount(sid));
            return Marshal.ReadInt32(GetSidSubAuthority(sid, (uint)(count - 1)));
        } finally {
            Marshal.FreeHGlobal(b);
            CloseHandle(t);
        }
    }

    // --- the Inno Setup wizard, clicked through with its defaults ---
    [DllImport("user32.dll")]
    static extern bool IsWindowEnabled(IntPtr hwnd);
    [DllImport("user32.dll")]
    static extern int GetWindowLong(IntPtr hwnd, int index);

    public static string[] WindowClasses(uint pid) {
        List<string> found = new List<string>();
        EnumWindows(delegate (IntPtr h, IntPtr p) {
            if (IsWindowVisible(h) && PidOf(h) == pid) found.Add(ClassOf(h) + " '" + TextOf(h) + "'");
            return true;
        }, IntPtr.Zero);
        return found.ToArray();
    }

    // Presses the default button of the process's visible setup window: OK of
    // the language dialog, Next / Install / Finish of the wizard (while it
    // installs, Next is hidden and nothing is pressed). A button whose caption
    // is in skip (cancel) or starts with "<" (back) is never pressed. Returns
    // what was pressed, "" when nothing was.
    public static string SetupStep(uint pid, string[] skip) {
        string done = "";
        EnumWindows(delegate (IntPtr h, IntPtr p) {
            if (done.Length > 0 || !IsWindowVisible(h) || PidOf(h) != pid) return true;
            string cls = ClassOf(h);
            if (cls != "TSelectLanguageForm" && cls != "TWizardForm") return true;
            List<IntPtr> buttons = new List<IntPtr>();
            EnumChildWindows(h, delegate (IntPtr c, IntPtr q) {
                string cc = ClassOf(c);
                bool isDefault = (GetWindowLong(c, -16) & 0x0F) == 0x01; // GWL_STYLE, BS_DEFPUSHBUTTON
                if ((cc == "TNewButton" || cc == "Button") && isDefault && IsWindowVisible(c) && IsWindowEnabled(c)) buttons.Add(c);
                return true;
            }, IntPtr.Zero);
            foreach (IntPtr b in buttons) {
                string text = TextOf(b).Replace("&", "").Trim();
                if (text.StartsWith("<") || Array.IndexOf(skip, text) >= 0 || text.Length == 0) continue;
                PostMessage(b, 0x00F5, IntPtr.Zero, IntPtr.Zero); // BM_CLICK
                done = cls + ": " + text;
                break;
            }
            return true;
        }, IntPtr.Zero);
        return done;
    }
}
'@

# Menu item ids: systray numbers items AND separators from 1 in creation order
# (internal/ui/tray.go): status 1, sep 2, toggle 3, sep 4, import x2 5-6,
# subscriptions 7, settings 8, sing-box update 9, app update 10, sep 11,
# DPI 12, autostart 13, sep 14, quit 15
$menuToggle = 3
$menuSettings = 8
$menuSingBoxUpdate = 9
$menuQuit = 15

# --- helpers ---------------------------------------------------------------

$pf = Join-Path $env:ProgramFiles 'SingBoxTray'
$pd = Join-Path $env:ProgramData 'SingBoxTray'
$exe = Join-Path $pf 'tray-sing-box.exe'
$sb = Join-Path $pf 'sing-box.exe'
$appLog = Join-Path $pd 'tray-sing-box.log'

# Processes by FULL image path
function Procs([string]$path) {
    $name = Split-Path -Leaf $path
    @(Get-CimInstance Win32_Process -Filter "Name='$name'" |
        Where-Object { $_.ExecutablePath -and ($_.ExecutablePath -ieq $path) })
}

function Running([string]$path) { return (@(Procs $path).Count -gt 0) }

function FirstPid([string]$path) {
    $p = @(Procs $path)
    if ($p.Count -eq 0) { return 0 }
    return [int]$p[0].ProcessId
}

# Still the same live process (a PID of 0 - nothing ran - is never "the same")
function SamePid([string]$path, [int]$before) { return ($before -ne 0 -and (FirstPid $path) -eq $before) }

# The start-up restore checks the started sing-box for a few seconds and only
# then hands over to the monitor: a phase that kills sing-box, or reads the
# restore's log line, waits for it first
function RestoreDone { return (WaitFor { (LastSession) -match 'VPN state restored on attempt \d' } 60) }

function WaitFor([scriptblock]$cond, [int]$seconds) {
    $deadline = (Get-Date).AddSeconds($seconds)
    while ((Get-Date) -lt $deadline) {
        if (& $cond) { return $true }
        Start-Sleep -Milliseconds 500
    }
    return [bool](& $cond)
}

# Not Start-Process -Wait: it also waits for every child process
function RunWait([string]$file, [string[]]$argList, [int]$seconds = 300) {
    $p = Start-Process -FilePath $file -ArgumentList $argList -PassThru
    $null = $p.Handle # keeps ExitCode readable after the exit
    if (-not $p.WaitForExit($seconds * 1000)) {
        Log "$file did not exit within $seconds s"
        return -999
    }
    return $p.ExitCode
}

function Intent {
    $v = Get-ItemProperty -Path 'HKCU:\Software\SingBoxTray' -Name VPNRunning -ErrorAction SilentlyContinue
    if ($v) { return [int]$v.VPNRunning }
    return $null
}

function TaskCommand {
    $out = & schtasks.exe /Query /TN SingBoxTray /XML 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $out) { return '' }
    return [string]([xml]($out -join "`n")).Task.Actions.Exec.Command
}

# The app log is held open for appending: read it shared
function LogBytes {
    if (-not (Test-Path $appLog)) { return [byte[]]@() }
    $fs = [IO.File]::Open($appLog, 'Open', 'Read', 'ReadWrite')
    try {
        $buf = New-Object byte[] $fs.Length
        $n = $fs.Read($buf, 0, $buf.Length)
        if ($n -lt $buf.Length) { $buf = $buf[0..($n - 1)] }
        return , $buf
    }
    finally { $fs.Dispose() }
}

function LogMark { return (LogBytes).Length }

function LogSince([long]$mark) {
    $b = LogBytes
    if ($b.Length -le $mark) { return '' }
    return [Text.Encoding]::UTF8.GetString($b, [int]$mark, $b.Length - [int]$mark)
}

# The current run of the app (after the last start banner)
function LastSession {
    $text = LogSince 0
    $i = $text.LastIndexOf('=== Application started ===')
    if ($i -lt 0) { return $text }
    return $text.Substring($i)
}

function TrayWindow {
    $p = FirstPid $exe
    if ($p -eq 0) { return [IntPtr]::Zero }
    return [SbWin]::TrayWindow([uint32]$p)
}

function IconShown {
    $h = TrayWindow
    if ($h -eq [IntPtr]::Zero) { return $false }
    return ([SbWin]::IconState($h, 100) -eq 0)
}

# The same query for an icon the app never registered must fail - otherwise
# IconShown proves nothing
function IconCheckValid {
    $h = TrayWindow
    if ($h -eq [IntPtr]::Zero) { return $false }
    return ([SbWin]::IconState($h, 4242) -ne 0)
}

function MenuClick([int]$id) {
    $h = TrayWindow
    if ($h -eq [IntPtr]::Zero) { Log "no tray window for menu item $id"; return $false }
    return [SbWin]::Command($h, $id)
}

function DialogTexts {
    $p = FirstPid $exe
    if ($p -eq 0) { return @() }
    return @([SbWin]::Dialogs([uint32]$p) | ForEach-Object { [SbWin]::DialogText($_) })
}

# Any popup is a failure in the phases that expect none (the give-up report
# of the monitor, an error box)
function CheckNoPopup([string]$name) {
    $d = @(DialogTexts)
    $detail = ''
    if ($d.Count -gt 0) { $detail = ($d -join ' || ') }
    Check $name ($d.Count -eq 0) $detail
}

# --- the settings page in a real browser -------------------------------------
# Edge is started with a DevTools port first; the tray item opens the one-time
# login link the usual way (the shell opens it in the default browser), which
# lands as a tab in that instance. The page is then driven through the
# DevTools protocol: it runs its own handlers, as a click would.

$edgeExe = @("${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe", "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe") |
    Where-Object { Test-Path $_ } | Select-Object -First 1

# The sandbox image lacks the open command of Edge's URL class (a link then
# ends in "Pick an app"); DevTools refuse Edge's default profile folder, the
# policy moves it
function PrepareBrowser {
    $k = 'HKCU:\Software\Classes\MSEdgeHTM\shell\open\command'
    New-Item -Path $k -Force | Out-Null
    Set-Item -Path $k -Value ('"' + $edgeExe + '" --single-argument %1')
    $pol = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
    New-Item -Path $pol -Force | Out-Null
    Set-ItemProperty -Path $pol -Name HideFirstRunExperience -Value 1 -Type DWord
    Set-ItemProperty -Path $pol -Name UserDataDir -Value 'C:\edge-e2e' -Type String
    # Started by the shell, with its token, like any browser of the user: the
    # link the app opens through the shell must reach this instance (with UAC
    # on, an elevated Edge would not take it)
    New-Item -ItemType Directory -Force 'C:\e2e' | Out-Null
    Set-Content -Path 'C:\e2e\edge.cmd' -Encoding ASCII -Value ('@start "" "' + $edgeExe + '" --remote-debugging-port=9222 about:blank')
    Start-Process -FilePath (Join-Path $env:windir 'explorer.exe') -ArgumentList 'C:\e2e\edge.cmd'
    return (WaitFor { try { [bool](Invoke-RestMethod -Uri 'http://127.0.0.1:9222/json/version' -TimeoutSec 2) } catch { $false } } 30)
}

function UacOn {
    $v = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -ErrorAction SilentlyContinue
    return ($v -and [int]$v.EnableLUA -ne 0)
}

function LevelOf([int]$procId) { return [SbWin]::Level($procId) }

# The shell's integrity level (the level of the user's normal programs)
function ShellLevel {
    $e = @(Get-Process -Name explorer -ErrorAction SilentlyContinue)
    if ($e.Count -eq 0) { return -1 }
    return (LevelOf $e[0].Id)
}

# Captions the setup wizard driver never presses: "Cancel" (ru, en)
$setupSkip = [string[]]@((-join [char[]](0x41E, 0x442, 0x43C, 0x435, 0x43D, 0x430)), 'Cancel')

# Windows PowerShell writes a JSON array from Invoke-RestMethod as ONE object:
# stored first, it is enumerated
function Pages {
    try { $all = Invoke-RestMethod -Uri 'http://127.0.0.1:9222/json' -TimeoutSec 5 } catch { return @() }
    return @($all | Where-Object { $_.type -eq 'page' })
}

$script:cdpSeq = 0
function CdpOpen([string]$url) {
    $ws = New-Object System.Net.WebSockets.ClientWebSocket
    [void]$ws.ConnectAsync([Uri]$url, [Threading.CancellationToken]::None).Wait(10000)
    if ($ws.State -ne [Net.WebSockets.WebSocketState]::Open) { throw "DevTools: no connection to $url" }
    return $ws
}

function CdpCall($ws, [string]$method, [hashtable]$params) {
    $script:cdpSeq++
    $seq = $script:cdpSeq
    $bytes = [Text.Encoding]::UTF8.GetBytes((@{ id = $seq; method = $method; params = $params } | ConvertTo-Json -Depth 10 -Compress))
    $seg = New-Object 'System.ArraySegment[byte]' -ArgumentList @(, $bytes)
    if (-not $ws.SendAsync($seg, [Net.WebSockets.WebSocketMessageType]::Text, $true, [Threading.CancellationToken]::None).Wait(10000)) { throw "DevTools: $method not sent" }
    $buf = New-Object byte[] 262144
    while ($true) {
        $ms = New-Object IO.MemoryStream
        do {
            $t = $ws.ReceiveAsync((New-Object 'System.ArraySegment[byte]' -ArgumentList @(, $buf)), [Threading.CancellationToken]::None)
            if (-not $t.Wait(60000)) { throw "DevTools: no answer to $method" }
            $ms.Write($buf, 0, $t.Result.Count)
        } while (-not $t.Result.EndOfMessage)
        $o = [Text.Encoding]::UTF8.GetString($ms.ToArray()) | ConvertFrom-Json
        if ($o.id -eq $seq) { return $o }
    }
}

# Evaluates a JavaScript expression in the page (promises awaited); $null on
# an exception
function Js($ws, [string]$expr) {
    $r = CdpCall $ws 'Runtime.evaluate' @{ expression = $expr; returnByValue = $true; awaitPromise = $true }
    if ($r.result.exceptionDetails) { Log "js exception: $($r.result.exceptionDetails.text) in: $expr"; return $null }
    return $r.result.result.value
}

# A PowerShell string as a JavaScript string literal
function JsString([string]$s) { return (ConvertTo-Json -InputObject $s -Compress) }

function ConfigText {
    $f = Join-Path $pd 'config.json'
    if (-not (Test-Path $f)) { return '' }
    return [string](Get-Content -Path $f -Raw -Encoding UTF8)
}

function ConfigJson { return (ConfigText | ConvertFrom-Json) }

# A subscription provider on 127.0.0.1:18081 (any path): two share links,
# base64 as providers serve them; documentation-only addresses. Runs in a job
# until StopSubscriptionProvider.
function StartSubscriptionProvider {
    $links = @(
        'vless://22222222-3333-4444-5555-666666666666@192.0.2.10:443?security=tls&sni=example.com&type=tcp#sub-node-1',
        'trojan://secret-password@192.0.2.11:443?sni=example.com#sub-node-2'
    ) -join "`n"
    $body = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($links))
    Remove-Item -LiteralPath 'C:\e2e\sub.stop' -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Force 'C:\e2e' | Out-Null
    $job = Start-Job -ScriptBlock {
        param($body)
        $l = New-Object System.Net.HttpListener
        $l.Prefixes.Add('http://127.0.0.1:18081/')
        $l.Start()
        while (-not (Test-Path 'C:\e2e\sub.stop')) {
            $t = $l.GetContextAsync()
            while (-not $t.Wait(500)) { if (Test-Path 'C:\e2e\sub.stop') { break } }
            if (-not $t.IsCompleted) { break }
            $bytes = [Text.Encoding]::ASCII.GetBytes($body)
            $t.Result.Response.ContentType = 'text/plain'
            $t.Result.Response.OutputStream.Write($bytes, 0, $bytes.Length)
            $t.Result.Response.Close()
        }
        $l.Stop()
    } -ArgumentList $body
    [void](WaitFor { try { [bool](Invoke-WebRequest -Uri 'http://127.0.0.1:18081/probe' -UseBasicParsing -TimeoutSec 2) } catch { $false } } 20)
    return $job
}

function StopSubscriptionProvider($job) {
    New-Item -ItemType File -Force 'C:\e2e\sub.stop' | Out-Null
    [void](Wait-Job $job -Timeout 10)
    Remove-Job $job -Force
}

Log "start, $([Environment]::OSVersion.VersionString)"

# --- phases ------------------------------------------------------------------

switch ($Phase) {
    'install' {
        $code = RunWait (Join-Path $root 'setup.exe') @('/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', '/SP-', '/TASKS=autostart', "/LOG=$res\setup.log") 600
        Check 'setup exit code 0' ($code -eq 0) "code $code"
        Check 'exe in Program Files' (Test-Path $exe)
        Check 'autostart task launches it' ((TaskCommand) -ieq $exe) (TaskCommand)
        Check 'data dir created' (Test-Path $pd)
        Copy-Item -Path (Join-Path $root 'payload\sing-box.exe') -Destination $pf
        Get-ChildItem -Path (Join-Path $root 'payload') -Filter '*.dll' | Copy-Item -Destination $pf
        Copy-Item -Path (Join-Path $root 'payload\config.json') -Destination $pd
        New-Item -Path 'HKCU:\Software\SingBoxTray' -Force | Out-Null
        Set-ItemProperty -Path 'HKCU:\Software\SingBoxTray' -Name VPNRunning -Value 1 -Type DWord
        & schtasks.exe /Run /TN SingBoxTray | Out-Null
        Check 'the task starts the app' (WaitFor { Running $exe } 60)
        Check 'the VPN intent is restored' (WaitFor { Running $sb } 60)
        Check 'tray icon shown' (WaitFor { IconShown } 60)
        $s = LastSession
        $ver = ''
        if ($s -match 'Version: (\S+)') { $ver = $Matches[1] }
        Check 'log: installed layout' ($s -match 'Layout: installed') $ver
        Check 'log: the restore finished' (RestoreDone)
        CheckNoPopup 'no popup'
    }

    'fresh' {
        $code = RunWait (Join-Path $root 'setup.exe') @('/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', '/SP-', '/TASKS=autostart', "/LOG=$res\setup.log") 600
        Check 'setup exit code 0' ($code -eq 0) "code $code"
        Check 'autostart task launches it' ((TaskCommand) -ieq $exe) (TaskCommand)
        & schtasks.exe /Run /TN SingBoxTray | Out-Null
        Check 'the task starts the app' (WaitFor { Running $exe } 60)
        Check 'tray icon shown' (WaitFor { IconShown } 60)
        Check 'no config.json' (-not (Test-Path (Join-Path $pd 'config.json')))
        Check 'no sing-box.exe' (-not (Test-Path $sb))
        Check 'no VPN intent' ($null -eq (Intent))
        CheckNoPopup 'no popup'
    }

    'web' {
        Check 'browser with DevTools' (PrepareBrowser)
        $edge = @(Get-CimInstance Win32_Process -Filter "Name='msedge.exe'" | Where-Object { $_.CommandLine -match 'remote-debugging-port' })[0]
        $edgeLevel = -1
        if ($edge) { $edgeLevel = LevelOf ([int]$edge.ProcessId) }
        Check 'the browser runs with the shell token' ($edgeLevel -gt 0 -and $edgeLevel -eq (ShellLevel)) "browser $edgeLevel, shell $(ShellLevel), app $(LevelOf (FirstPid $exe)), UAC $(UacOn)"
        $before = @(Pages | ForEach-Object { $_.id })
        Check 'menu: settings' (MenuClick $menuSettings)
        $page = $null
        $ok = WaitFor { $script:page = @(Pages | Where-Object { $_.url -match '^http://127\.0\.0\.1:\d+/' -and $before -notcontains $_.id })[0]; [bool]$script:page } 30
        Check 'the tray item opens the settings page' $ok
        if (-not $ok) { Finish 'no settings page' }
        $ws = CdpOpen $page.webSocketDebuggerUrl
        Check 'page loaded' (WaitFor { (Js $ws 'document.readyState') -eq 'complete' } 20)
        $href = Js $ws 'location.href'
        Check 'login code gone from the address bar' (-not ($href -match 'code=')) $href
        Check 'first-config section shown' (WaitFor { (Js $ws "!document.getElementById('setup').hidden") -eq $true } 15)

        # 1. sing-box from GitHub (the sandbox has the network for this phase)
        [void](Js $ws "document.querySelector('#setup button.secondary').click(); true")
        Check 'sing-box downloaded from the page' (WaitFor { Test-Path $sb } 300)
        [void](WaitFor { (Js $ws "!document.querySelector('#setup button.secondary').disabled") -eq $true } 120)
        Check 'the page reports it' ((Js $ws "document.getElementById('msg').className") -eq 'ok') (Js $ws "document.getElementById('msg').textContent")

        # 2. a config with a listener off the loopback is refused, nothing written
        $create = "(async () => { document.getElementById('setup-config').value = CONFIG; await createConfig(document.querySelector('#setup button:not(.secondary)')); const m = document.getElementById('msg'); return m.className + '|' + m.textContent; })()"
        $r = Js $ws $create.Replace('CONFIG', (JsString (Get-Content (Join-Path $root 'payload\web-risky.json') -Raw)))
        Check 'the guard refuses a listener off the loopback' (($r -match '^err\|') -and ($r -match 'external_controller')) $r
        Check 'nothing written' (-not (Test-Path (Join-Path $pd 'config.json')))

        # 3. the real first config
        $r = Js $ws $create.Replace('CONFIG', (JsString (Get-Content (Join-Path $root 'payload\web-config.json') -Raw)))
        Check 'first config saved' ($r -match '^ok\|') $r
        Check 'config.json written' (Test-Path (Join-Path $pd 'config.json'))
        Check 'first-config section gone' ((Js $ws "document.getElementById('setup').hidden") -eq $true)
        $ob = [string](Js $ws "document.getElementById('outbounds').value")
        $masked = Js $ws "document.getElementById('outbounds').value.includes('(\u0441\u043a\u0440\u044b\u0442\u043e)')"
        Check 'the uuid never reaches the page' (($ob -match 'test-vless') -and -not ($ob -match '11111111-2222') -and $masked -eq $true)

        # 4. VPN on from the page
        $r = Js $ws "(async () => { await toggleVPN(); return document.getElementById('msg').className; })()"
        Check 'VPN on from the page' (WaitFor { Running $sb } 30) $r
        Check 'intent saved: 1' (WaitFor { (Intent) -eq 1 } 30) "intent $(Intent)"

        # 5. saving a section (unchanged) restarts the running VPN - an
        # internal restart: the intent is not written
        $old = FirstPid $sb
        $mark = LogMark
        [void](Js $ws "document.querySelector('button[onclick*=route]').click(); true")
        Check 'saving route restarts sing-box' (WaitFor { $n = FirstPid $sb; $n -ne 0 -and $n -ne $old } 30) "PID $old -> $(FirstPid $sb)"
        [void](WaitFor { (Js $ws "!document.querySelector('button[onclick*=route]').disabled") -eq $true } 30)
        $new = LogSince $mark
        Check 'log: saved, restarted, intent untouched' (($new -match 'Settings: section "route" saved') -and ($new -match 'Restarting VPN to apply configuration changes') -and -not ($new -match 'VPN state saved')) (Js $ws "document.getElementById('msg').textContent")
        Check 'backup and history kept' ((Test-Path (Join-Path $pd 'config.json.bak')) -and @(Get-ChildItem (Join-Path $pd 'config-history') -Filter 'config-*.json' -ErrorAction SilentlyContinue).Count -ge 1)
        Check 'intent still 1' ((Intent) -eq 1) "intent $(Intent)"

        # 6. off and on again from the page
        [void](WaitFor { (Js $ws "document.getElementById('vpn-btn').dataset.want === 'false' && !document.getElementById('vpn-btn').disabled") -eq $true } 15)
        [void](Js $ws "(async () => { await toggleVPN(); return true; })()")
        Check 'VPN off from the page' (WaitFor { -not (Running $sb) } 30)
        Check 'intent saved: 0' (WaitFor { (Intent) -eq 0 } 15) "intent $(Intent)"
        [void](Js $ws "(async () => { await toggleVPN(); return true; })()")
        Check 'VPN on again from the page' (WaitFor { Running $sb } 30)
        Check 'intent saved: 1 again' (WaitFor { (Intent) -eq 1 } 30) "intent $(Intent)"

        # 7. the active server: the choice repoints route.final and restarts
        $old = FirstPid $sb
        [void](Js $ws "(() => { document.querySelector('#outbound-list input[value=test-vless]').checked = true; switchOutbound(); return true; })()")
        Check 'switch: route.final is the chosen server' (WaitFor { (ConfigJson).route.final -eq 'test-vless' } 30)
        Check 'switch: sing-box restarted' (WaitFor { $n = FirstPid $sb; $n -ne 0 -and $n -ne $old } 30)

        # 8. the config history rolls the switch back
        $n = Js $ws "(async () => { await refreshHistory(); return document.querySelectorAll('#history-list button').length; })()"
        Check 'history lists the saved versions' ($n -ge 2) "$n versions"
        $old = FirstPid $sb
        $mark = LogMark
        [void](Js $ws "(() => { window.confirm = () => true; document.querySelector('#history-list button').click(); return true; })()")
        Check 'restore: route.final back' (WaitFor { (ConfigJson).route.final -eq 'direct' } 30)
        Check 'restore: sing-box restarted' (WaitFor { $p = FirstPid $sb; $p -ne 0 -and $p -ne $old } 30)
        Check 'log: rolled back' (WaitFor { (LogSince $mark) -match 'config rolled back to' } 10)

        # 9. a subscription from a provider (a local one): its servers join the
        # config; the page shows the URL without its path (the token)
        $job = StartSubscriptionProvider
        [void](Js $ws "(() => { document.getElementById('sub-url').value = 'http://127.0.0.1:18081/sub-token-abc'; addSubscription(document.querySelector('button[onclick*=addSubscription]')); return true; })()")
        Check 'subscription: servers added' (WaitFor { $c = ConfigText; ($c -match 'sub-node-1') -and ($c -match 'sub-node-2') } 60) (Js $ws "document.getElementById('msg').textContent")
        [void](WaitFor { (Js $ws "document.getElementById('subs-list').textContent.includes('127.0.0.1')") -eq $true } 15)
        $subs = [string](Js $ws "document.getElementById('subs-list').textContent")
        Check 'subscription: listed without its token' (($subs -match '127\.0\.0\.1') -and -not ($subs -match 'sub-token-abc')) $subs
        $ob = [string](Js $ws "document.getElementById('outbounds').value")
        Check 'subscription: its credentials masked' (($ob -match 'sub-node-1') -and -not ($ob -match '22222222-3333') -and -not ($ob -match 'secret-password'))
        [void](Js $ws "(() => { window.confirm = () => true; const b = document.querySelectorAll('#subs-list .sub button'); b[b.length - 1].click(); return true; })()")
        Check 'subscription: removed with its servers' (WaitFor { -not ((ConfigText) -match 'sub-node-') } 30)
        StopSubscriptionProvider $job

        # 10. the logs section
        $logs = [string](Js $ws "(async () => { await refreshLogs(null); return document.getElementById('logs-box').textContent; })()")
        Check 'logs: the app log is shown' ($logs -match 'Application started')

        # 11. a reload has no session; the tray item opens a new one
        [void](Js $ws 'location.reload(); true')
        Check 'a reloaded page has no session' (WaitFor { (Js $ws "document.readyState === 'complete' && !document.getElementById('nosession').hidden && document.getElementById('app').hidden") -eq $true } 20)
        $ws.Dispose()
        $before = @(Pages | ForEach-Object { $_.id })
        [void](MenuClick $menuSettings)
        $ok = WaitFor { $script:page = @(Pages | Where-Object { $_.url -match '^http://127\.0\.0\.1:\d+/' -and $before -notcontains $_.id })[0]; [bool]$script:page } 30
        $ok2 = $false
        if ($ok) {
            $ws = CdpOpen $page.webSocketDebuggerUrl
            $ok2 = WaitFor { (Js $ws "document.readyState === 'complete' && document.getElementById('nosession').hidden && document.getElementById('outbounds').value.includes('test-vless')") -eq $true } 20
            $ws.Dispose()
        }
        Check 'the tray item logs in again' ($ok -and $ok2)
        CheckNoPopup 'no popup'
    }

    'dir-refused' {
        # Outside Program Files the folder is usually user-writable, and the
        # autostart task would run an exe any program may replace. Run it on a
        # clean machine and again over an installation (there the directory
        # page is skipped): one refusal, exit code 7 ("cannot proceed"), no
        # dialog waiting for a click, the installation untouched
        $dir = 'C:\SingBoxTray'
        $installed = Test-Path $exe
        $app = FirstPid $exe
        $task = TaskCommand
        $code = RunWait (Join-Path $root 'setup.exe') @('/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', '/SP-', '/TASKS=autostart', "/DIR=$dir", "/LOG=$res\setup-dir.log") 120
        Log "over an installation: $installed"
        Check 'the silent setup ends by itself' ($code -ne -999) "code $code"
        if ($code -eq -999) {
            Get-CimInstance Win32_Process -Filter "Name='setup.exe' OR Name='setup.tmp'" | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
        }
        Check 'refused with exit code 7' ($code -eq 7) "code $code"
        Check 'the reason is in the setup log' ((Get-Content -Path "$res\setup-dir.log" -Raw -Encoding UTF8) -match 'Program Files')
        Check 'nothing installed there' (-not (Test-Path (Join-Path $dir 'tray-sing-box.exe')))
        Check 'autostart task unchanged' ((TaskCommand) -eq $task) "$(TaskCommand)"
        if ($installed -and $app -ne 0) { Check 'the running app untouched' (SamePid $exe $app) }
    }

    'interactive' {
        # The user's way: the setup started from the desktop (with UAC on: a
        # normal token, which the setup elevates), the wizard clicked through
        # with its defaults, the app launched by the last page (without
        # "runascurrentuser" that launch fails with code 740)
        New-Item -ItemType Directory -Force 'C:\e2e' | Out-Null
        Copy-Item -Path (Join-Path $root 'setup.exe') -Destination 'C:\e2e\setup.exe' -Force
        Start-Process -FilePath (Join-Path $env:windir 'explorer.exe') -ArgumentList 'C:\e2e\setup.exe'
        $boot = $null
        [void](WaitFor { $script:boot = @(Get-CimInstance Win32_Process -Filter "Name='setup.exe'" | Where-Object { $_.ExecutablePath -ieq 'C:\e2e\setup.exe' })[0]; [bool]$script:boot } 30)
        $bootLevel = -1
        if ($boot) { $bootLevel = LevelOf ([int]$boot.ProcessId) }
        Check 'the shell starts the setup' ([bool]$boot) "setup $bootLevel, shell $(ShellLevel), UAC $(UacOn)"
        if (UacOn) { Check 'UAC: the setup starts with a normal token' ($bootLevel -gt 0 -and $bootLevel -lt 0x3000) "level $bootLevel" }
        $steps = New-Object System.Collections.ArrayList
        $boxes = New-Object System.Collections.ArrayList
        $idle = 0
        $deadline = (Get-Date).AddSeconds(300)
        while ((Get-Date) -lt $deadline) {
            $tmp = @(Get-CimInstance Win32_Process -Filter "Name='setup.tmp'")
            foreach ($t in $tmp) {
                $tp = [uint32]$t.ProcessId
                foreach ($d in [SbWin]::Dialogs($tp)) {
                    # Any message box is a failure (e.g. "CreateProcess failed;
                    # code 740"): recorded, then closed with IDOK
                    $x = [SbWin]::DialogText($d)
                    if (-not $boxes.Contains($x)) { [void]$boxes.Add($x); Log "setup message box: $x" }
                    [void][SbWin]::CloseBox($d)
                }
                $st = [SbWin]::SetupStep($tp, $setupSkip)
                if ($st) { [void]$steps.Add($st); Log "wizard: $st"; $idle = 0 }
                else {
                    $idle++
                    if ($idle -eq 20) { Log ("setup windows: " + ([SbWin]::WindowClasses($tp) -join ' | ')) }
                }
            }
            if ($tmp.Count -eq 0 -and $steps.Count -gt 0) { break }
            Start-Sleep -Milliseconds 1500
        }
        Check 'the wizard went through' ($steps.Count -ge 3) ($steps -join ' | ')
        Check 'no setup message box' ($boxes.Count -eq 0) ($boxes -join ' || ')
        Check 'the last page started the app' (WaitFor { Running $exe } 30)
        $app = FirstPid $exe
        Check 'the app runs elevated' ((LevelOf $app) -ge 0x3000) "level $(LevelOf $app)"
        Check 'autostart task launches it' ((TaskCommand) -ieq $exe) (TaskCommand)
        Check 'tray icon shown' (WaitFor { IconShown } 60)
        CheckNoPopup 'no popup'
    }

    'singbox-update' {
        # (networked, after install) the tray item replaces a running older
        # sing-box with the latest release: download while the VPN runs, stop,
        # swap (the old binary kept as .old), start again; the intent stays
        $old = FirstPid $sb
        $before = ((& $sb version 2>$null) | Select-Object -First 1)
        Check 'VPN running' ($old -ne 0 -and (Intent) -eq 1) $before
        $mark = LogMark
        Check 'menu: update sing-box' (MenuClick $menuSingBoxUpdate)
        $d = $null
        $ok = WaitFor { $script:d = @([SbWin]::Dialogs([uint32](FirstPid $exe)))[0]; [bool]$script:d } 300
        $text = ''
        if ($ok) { $text = [SbWin]::DialogText($d); [void][SbWin]::CloseBox($d) }
        Check 'the result is reported' $ok $text
        if ($ok) { Check 'the report closes with OK' (WaitFor { -not [SbWin]::Exists($d) } 10) }
        $after = ((& $sb version 2>$null) | Select-Object -First 1)
        Check 'a newer sing-box is installed' ($after -and $after -ne $before) "$before -> $after"
        Check 'the previous binary kept as .old' (Test-Path "$sb.old")
        Check 'the VPN runs the new binary' (WaitFor { $n = FirstPid $sb; $n -ne 0 -and $n -ne $old } 30) "PID $old -> $(FirstPid $sb)"
        Check 'intent untouched: 1' ((Intent) -eq 1) "intent $(Intent)"
        $new = LogSince $mark
        Check 'log: updated and restarted' ($new -match 'sing-box updated .* \(restarted: true\)')
        Check 'no staging folder left' (@(Get-ChildItem -Path $pf -Directory -Filter '.sing-box-update-*' -Force -ErrorAction SilentlyContinue).Count -eq 0)
        CheckNoPopup 'no popup'
    }

    'cancel' {
        # While sing-box cannot start ("starting"), the tray toggle calls the
        # attempts off: intent 0, no more attempts, no give-up report
        $cfg = Join-Path $pd 'config.json'
        $old = FirstPid $sb
        Check 'VPN running' ($old -ne 0 -and (Intent) -eq 1)
        Rename-Item -Path $cfg -NewName 'config.json.off'
        $mark = LogMark
        Stop-Process -Id $old -Force
        Check 'the attempts run' (WaitFor { (LogSince $mark) -match 'auto-restarting \(attempt 2/' } 60)
        Check 'menu: toggle' (MenuClick $menuToggle)
        Check 'intent saved: 0' (WaitFor { (Intent) -eq 0 } 15) "intent $(Intent)"
        $at = LogMark
        Check 'no attempts after the stop' (-not (WaitFor { (LogSince $at) -match 'auto-restarting' } 40))
        Check 'no give-up report' (@(DialogTexts).Count -eq 0) (@(DialogTexts) -join ' || ')
        Rename-Item -Path (Join-Path $pd 'config.json.off') -NewName 'config.json'
        Check 'menu: toggle again' (MenuClick $menuToggle)
        Check 'the VPN starts again' (WaitFor { Running $sb } 30)
        Check 'intent saved: 1' (WaitFor { (Intent) -eq 1 } 30) "intent $(Intent)"
        CheckNoPopup 'no popup'
    }

    'crash' {
        $tray = FirstPid $exe
        [void](RestoreDone)
        $old = FirstPid $sb
        Check 'sing-box running' ($old -ne 0) "PID $old"
        $mark = LogMark
        Stop-Process -Id $old -Force
        Check 'the monitor restarts sing-box' (WaitFor { $n = FirstPid $sb; $n -ne 0 -and $n -ne $old } 60) "new PID $(FirstPid $sb)"
        # "running" once the restarted process survived the start grace
        Check 'log: running again' (WaitFor { (LogSince $mark) -match 'VPN status changed: \S+ -> running' } 30)
        $new = LogSince $mark
        Check 'log: the death is an ERROR' ($new -match "ERROR: sing-box \(PID $old\) exited with error")
        Check 'log: auto-restart attempt 1' ($new -match 'auto-restarting \(attempt 1/')
        Check 'intent untouched: 1' ((Intent) -eq 1) "intent $(Intent)"
        Check 'log: counter reset after a minute up' (WaitFor { (LogSince $mark) -match 'crash auto-restart counter reset' } 90)
        Check 'tray app untouched' (SamePid $exe $tray)
        CheckNoPopup 'no popup'
    }

    'explorer' {
        $tray = FirstPid $exe
        $sbPid = FirstPid $sb
        Check 'tray icon shown before' (IconShown)
        Check 'icon query rejects an unknown icon' (IconCheckValid)
        # With UAC on the shell runs below the app, and its "taskbar created"
        # broadcast reaches the app only through the app's message filter
        if (UacOn) { Check 'UAC: the shell runs below the app' ((ShellLevel) -gt 0 -and (ShellLevel) -lt (LevelOf $tray)) "shell $(ShellLevel), app $(LevelOf $tray)" }
        Get-Process -Name explorer -ErrorAction SilentlyContinue | Stop-Process -Force
        Check 'shell gone' (WaitFor { -not [SbWin]::ShellReady() } 10)
        $auto = WaitFor { [SbWin]::ShellReady() } 20
        if (-not $auto) {
            Log 'explorer did not come back by itself: starting it'
            Start-Process -FilePath (Join-Path $env:windir 'explorer.exe')
        }
        Check 'shell back' (WaitFor { [SbWin]::ShellReady() } 60) "restarted by Windows: $auto"
        Check 'tray icon back' (WaitFor { IconShown } 60)
        if (UacOn) { Check 'UAC: the new shell runs below the app too' ((ShellLevel) -gt 0 -and (ShellLevel) -lt (LevelOf $tray)) "shell $(ShellLevel)" }
        Check 'tray app survived' (SamePid $exe $tray)
        Check 'sing-box untouched' (SamePid $sb $sbPid)
        CheckNoPopup 'no popup'
    }

    'stop' {
        $sbPid = FirstPid $sb
        $mark = LogMark
        Check 'menu: toggle' (MenuClick $menuToggle)
        Check 'sing-box stops' (WaitFor { -not (Running $sb) } 30)
        Check 'intent saved: 0' ((Intent) -eq 0) "intent $(Intent)"
        $new = LogSince $mark
        Check 'log: ended by stop' ($new -match "sing-box \(PID $sbPid\) ended by stop")
        Check 'log: no ERROR for a requested stop' (-not ($new -match 'ERROR: sing-box'))
        Check 'stays off' (-not (WaitFor { Running $sb } 15))
        CheckNoPopup 'no popup'
    }

    'boot-off' {
        Check 'the task starts the app at logon' (WaitFor { Running $exe } 180)
        Check 'tray icon shown' (WaitFor { IconShown } 120)
        Check 'the VPN stays off' (-not (WaitFor { Running $sb } 20))
        Check 'intent still 0' ((Intent) -eq 0) "intent $(Intent)"
        $s = LastSession
        Check 'log: no restore attempt' (-not ($s -match 'VPN state restored|auto-restarting'))
        Check 'menu: toggle' (MenuClick $menuToggle)
        Check 'the VPN starts from the menu' (WaitFor { Running $sb } 30)
        # Saved once the process survived the start grace
        Check 'intent saved: 1' (WaitFor { (Intent) -eq 1 } 30) "intent $(Intent)"
        CheckNoPopup 'no popup'
    }

    'boot-on' {
        Check 'the task starts the app at logon' (WaitFor { Running $exe } 180)
        Check 'the VPN is restored' (WaitFor { Running $sb } 120)
        Check 'tray icon shown' (WaitFor { IconShown } 120)
        Check 'log: restored on attempt 1' (WaitFor { (LastSession) -match 'VPN state restored on attempt 1' } 30)
        CheckNoPopup 'no popup'
    }

    'update' {
        if (-not $ExpectVersion) { Finish 'no -ExpectVersion' }
        $want = $ExpectVersion.TrimStart('v')
        $tray = FirstPid $exe
        $sbPid = FirstPid $sb
        Check 'app and sing-box running' ($tray -ne 0 -and $sbPid -ne 0) "app $tray, sing-box $sbPid"
        $mark = LogMark
        # The first check runs 2 min after the start
        $first = [IntPtr]::Zero
        $ok = WaitFor {
            foreach ($d in [SbWin]::Dialogs([uint32]$tray)) {
                if ([SbWin]::DialogText($d) -match [regex]::Escape($want)) { $script:first = $d; return $true }
            }
            return $false
        } 400
        $text = ''
        if ($ok) { $text = [SbWin]::DialogText($first) }
        Check "offered $want" $ok $text
        if (-not $ok) { Finish 'no offer' }
        [void][SbWin]::AnswerYes($first)
        $second = [IntPtr]::Zero
        $ok = WaitFor {
            foreach ($d in [SbWin]::Dialogs([uint32]$tray)) {
                if ($d -ne $first -and [SbWin]::DialogText($d) -match [regex]::Escape($want)) { $script:second = $d; return $true }
            }
            return $false
        } 400
        $text = ''
        if ($ok) { $text = [SbWin]::DialogText($second) }
        Check 'installed, relaunch offered' $ok $text
        if (-not $ok) { Finish 'no relaunch question' }
        [void][SbWin]::AnswerYes($second)
        Check 'the old instance exits' (WaitFor { @(Procs $exe | Where-Object { [int]$_.ProcessId -eq $tray }).Count -eq 0 } 60)
        Check 'the new instance runs' (WaitFor { $n = FirstPid $exe; $n -ne 0 -and $n -ne $tray } 60) "PID $(FirstPid $exe)"
        Check 'sing-box kept running (same PID)' (SamePid $sb $sbPid) "PID $(FirstPid $sb)"
        Check 'previous exe kept as .old' (Test-Path "$exe.old")
        $v = (& $exe --version 2>$null | Out-String).Trim()
        Check "exe on disk is $ExpectVersion" ($v -match [regex]::Escape($want)) $v
        Check 'tray icon shown' (WaitFor { IconShown } 60)
        $new = LogSince $mark
        Check 'log: started after a self-update' ($new -match 'Started after a self-update')
        Check "log: Version: $ExpectVersion" ($new -match [regex]::Escape("Version: $ExpectVersion"))
        Check 'log: running sing-box adopted' ($new -match 'already running, not starting new instance')
        # The new instance checks again 2 min after its start: nothing to offer
        Check 'no second offer' (-not (WaitFor { @(DialogTexts).Count -gt 0 } 180)) (@(DialogTexts) -join ' || ')
    }

    'giveup' {
        # sing-box cannot start (config.json gone): "starting", 5 attempts with
        # a growing pause, then the yes/no report; "yes" turns the VPN off
        $cfg = Join-Path $pd 'config.json'
        $old = FirstPid $sb
        Check 'VPN running' ($old -ne 0 -and (Intent) -eq 1)
        Rename-Item -Path $cfg -NewName 'config.json.off'
        $mark = LogMark
        Stop-Process -Id $old -Force
        $d = $null
        $ok = WaitFor { $script:d = @([SbWin]::Dialogs([uint32](FirstPid $exe)))[0]; [bool]$script:d } 150
        $new = LogSince $mark
        $text = ''
        if ($ok) { $text = [SbWin]::DialogText($d) }
        Check 'report after the attempts' $ok $text
        Check 'log: 5 attempts' (($new -match 'auto-restarting \(attempt 5/5\)') -and -not ($new -match 'attempt 6/'))
        Check 'log: attempts failed on the missing config' ($new -match 'Crash auto-restart attempt 5 failed: .*config\.json')
        Check 'the report names the config' ($text -match 'config\.json')
        Check 'no sing-box meanwhile' (-not (Running $sb))
        Check 'intent kept until answered: 1' ((Intent) -eq 1) "intent $(Intent)"
        if ($ok) { [void][SbWin]::AnswerYes($d) }
        Check '"yes" records the VPN off' (WaitFor { (Intent) -eq 0 } 15) "intent $(Intent)"
        Check 'log: stop after the answer' ((LogSince $mark) -match 'VPNService\.Stop called')
        Check 'no further attempts' (-not (WaitFor { (LogSince $mark) -match 'attempt 6/|attempt 1/5\)[\s\S]*attempt 1/5\)' } 20))
        Rename-Item -Path (Join-Path $pd 'config.json.off') -NewName 'config.json'
        Check 'menu: toggle' (MenuClick $menuToggle)
        Check 'the VPN starts again' (WaitFor { Running $sb } 30)
        Check 'intent saved: 1' (WaitFor { (Intent) -eq 1 } 30) "intent $(Intent)"
        CheckNoPopup 'no popup'
    }

    'quit' {
        $sbPid = FirstPid $sb
        Check 'sing-box running' ($sbPid -ne 0)
        $mark = LogMark
        Check 'menu: quit' (MenuClick $menuQuit)
        Check 'the app exits' (WaitFor { -not (Running $exe) } 30)
        Start-Sleep -Seconds 5
        Check 'sing-box keeps running' (SamePid $sb $sbPid) "PID $(FirstPid $sb)"
        Check 'log: Quitting' ((LogSince $mark) -match 'Quitting')
    }

    'collect' {
        $dst = Join-Path $res 'logs'
        New-Item -ItemType Directory -Force $dst | Out-Null
        Get-ChildItem -Path $pd -File -Filter '*.log*' -ErrorAction SilentlyContinue | Copy-Item -Destination $dst -Force
        if (Test-Path "$res\setup.log") { Log 'setup log kept' }
        Check 'logs collected' (Test-Path (Join-Path $dst 'tray-sing-box.log'))
    }

    default { Finish "unknown phase $Phase" }
}

Finish
