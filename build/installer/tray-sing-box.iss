; Inno Setup script for Sing-Box VPN Tray Manager.
;
; Compiled by .github/workflows/release.yml:
;   iscc /DVersion=1.2.3 /DSource=..\..\dist\tray-sing-box-1.2.3-windows-amd64.exe build\installer\tray-sing-box.iss
; Locally (Inno Setup 6 installed):
;   iscc build\installer\tray-sing-box.iss            (uses bin\tray-sing-box.exe, version 0.0.0)
;
; Layout it produces (see internal/infrastructure/paths): the exe goes to
; Program Files, where only an administrator can write — the autostart task
; launches it elevated without a UAC prompt, so a user-writable location would
; let any program gain administrator rights at the next logon. The data
; (config.json, logs, subscriptions, history) goes to %ProgramData%\SingBoxTray,
; created by the app on first run. sing-box.exe is NOT bundled: the app
; downloads it from the official releases on request ("Обновить sing-box"),
; or takes it over from a previous portable installation (migration).

#ifndef Version
  #define Version "0.0.0"
#endif
#ifndef Source
  #define Source "..\..\bin\tray-sing-box.exe"
#endif
#define AppName "Sing-Box VPN Tray Manager"
#define ExeName "tray-sing-box.exe"

[Setup]
AppId={{7D0F0E0C-2B4E-4E1B-9C2A-5F6A7B8C9D01}
AppName={#AppName}
AppVersion={#Version}
AppVerName={#AppName} {#Version}
DefaultDirName={autopf}\SingBoxTray
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=..\..\dist
OutputBaseFilename=tray-sing-box-{#Version}-setup
SetupIconFile=..\..\assets\icons\tray.ico
UninstallDisplayIcon={app}\{#ExeName}
UninstallDisplayName={#AppName}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
; The running app is asked to quit by PrepareToInstall (below), not by the
; Restart Manager: the app is elevated and owns a hidden window only
CloseApplications=no

[Languages]
Name: "russian"; MessagesFile: "compiler:Languages\Russian.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Files]
Source: "{#Source}"; DestDir: "{app}"; DestName: "{#ExeName}"; Flags: ignoreversion
; The same exe, extractable to {tmp} by PrepareToInstall: on a fresh install
; there is no {app} copy yet to ask a running portable copy to quit with
Source: "{#Source}"; DestName: "{#ExeName}"; Flags: dontcopy

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#ExeName}"
Name: "{group}\{cm:UninstallProgram,{#AppName}}"; Filename: "{uninstallexe}"

[Tasks]
Name: "autostart"; Description: "Запускать при входе в Windows (задача планировщика, с правами администратора, без запроса UAC)"; Flags: checkedonce

[Run]
; Order matters. --migrate: first run of an installed copy takes over the
; portable installation the "SingBoxTray" task still points at (config,
; subscriptions, history, sing-box.exe; the old copy is stopped, its task
; deleted). It must run BEFORE --enable-autostart, which repoints the task at
; THIS exe (schtasks /F) — afterwards the old copy could not be found.
; Both run as the installing user: the task is bound to that account's SID.
Filename: "{app}\{#ExeName}"; Parameters: "--migrate"; Flags: runhidden waituntilterminated
Filename: "{app}\{#ExeName}"; Parameters: "--enable-autostart"; Flags: runhidden waituntilterminated; Tasks: autostart
; runascurrentuser: postinstall entries default to the original, non-elevated
; user, and the exe's requireAdministrator manifest then fails CreateProcess
; with code 740
Filename: "{app}\{#ExeName}"; Description: "Запустить {#AppName}"; Flags: nowait postinstall skipifsilent runascurrentuser
; A silent upgrade (/SILENT, /VERYSILENT) quit the running copy in
; PrepareToInstall and shows no "launch" checkbox: start it again
Filename: "{app}\{#ExeName}"; Flags: nowait; Check: RelaunchAfterSilentUpgrade

[UninstallRun]
; Only this installation's tray app: the quit event is global, and a portable
; copy the user runs instead must survive
Filename: "{app}\{#ExeName}"; Parameters: "--quit-installation"; Flags: runhidden waituntilterminated; RunOnceId: "quit"
; Stops the VPN of this installation, removes the scheduled task and the
; registry intent (the helper skips its own process)
Filename: "{app}\{#ExeName}"; Parameters: "--uninstall-cleanup"; Flags: runhidden waituntilterminated; RunOnceId: "cleanup"

[UninstallDelete]
; sing-box.exe (downloaded/migrated later) and the self-update backups were
; not installed by us but belong to this installation. Named explicitly, not
; "everything in {app}": installed outside Program Files (or with a
; config.json next to the exe) the app is portable and keeps its data here
Type: files; Name: "{app}\sing-box.exe"
Type: files; Name: "{app}\sing-box.exe.old"
Type: files; Name: "{app}\{#ExeName}.old"
Type: files; Name: "{app}\{#ExeName}.new"
Type: files; Name: "{app}\*.dll"
Type: files; Name: "{app}\*.dll.old"
Type: filesandordirs; Name: "{app}\.sing-box-update-*"
Type: filesandordirs; Name: "{app}\tmp"
Type: dirifempty; Name: "{app}"

[Code]
var
  WasRunning: Boolean;

// A running copy — in {app} (upgrade) or anywhere else (a portable copy of
// this rework, which holds the same single-instance mutex) — is asked to
// exit before the exe is copied: `--quit` of the NEW exe, extracted to
// {tmp}, signals the global quit event and waits. The VPN (sing-box) keeps
// running and is adopted again, or taken over by --migrate.
// Only under Program Files: elsewhere the folder is usually writable without
// elevation (an elevated autostart exe there would hand administrator rights
// to any program), and the app would run portable — no takeover, while the
// autostart task is repointed at an empty copy
function InProgramFiles(Dir: String): Boolean;
var
  D: String;
begin
  D := AddBackslash(Lowercase(Dir));
  Result := (Pos(AddBackslash(Lowercase(ExpandConstant('{commonpf64}'))), D) = 1) or
            (Pos(AddBackslash(Lowercase(ExpandConstant('{commonpf32}'))), D) = 1);
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  ResultCode: Integer;
begin
  Result := '';
  // /DIR= of a silent install bypasses the directory page
  if not InProgramFiles(ExpandConstant('{app}')) then
  begin
    Result := 'Приложение устанавливается только в Program Files: ' + ExpandConstant('{app}');
    exit;
  end;
  if FileExists(ExpandConstant('{app}\config.json')) then
  begin
    Result := 'В папке установки лежит config.json переносной копии: ' + ExpandConstant('{app}');
    exit;
  end;
  WasRunning := CheckForMutexes('Global\SingBoxTray-single-instance');
  ExtractTemporaryFile('{#ExeName}');
  // Non-zero: the copy did not exit within 30 s (a long operation such as a
  // sing-box download holds it) — stop here instead of failing on the
  // locked exe. A helper that could not be started at all is not a reason
  // to stop: then nothing of ours can be running a quit event either.
  if Exec(ExpandConstant('{tmp}\{#ExeName}'), '--quit', '', SW_HIDE, ewWaitUntilTerminated, ResultCode) and (ResultCode <> 0) then
    Result := 'Работающее приложение Sing-Box VPN Tray Manager не завершилось: вероятно, идёт долгая операция (обновление sing-box, подписок). Дождитесь её окончания и запустите установку снова.';
end;

function RelaunchAfterSilentUpgrade: Boolean;
begin
  Result := WizardSilent and WasRunning;
end;

// A folder with a config.json is a portable installation: installing into
// it would make the new copy portable too (data next to the exe, deleted
// with it) and defeat the takeover
function NextButtonClick(CurPageID: Integer): Boolean;
begin
  Result := True;
  if (CurPageID = wpSelectDir) and not InProgramFiles(WizardDirValue) then
  begin
    MsgBox('Приложение запускается автоматически с правами администратора, поэтому ставится только в Program Files — туда без прав администратора никто не может подменить файлы.', mbError, MB_OK);
    Result := False;
  end
  else if (CurPageID = wpSelectDir) and FileExists(AddBackslash(WizardDirValue) + 'config.json') then
  begin
    MsgBox('В этой папке лежит config.json переносной копии. Установите приложение в другую папку (по умолчанию — Program Files): при первом запуске оно само заберёт настройки и sing-box из переносной копии.', mbError, MB_OK);
    Result := False;
  end;
end;

// The data survives an uninstall unless the user says otherwise. A silent
// uninstall never asks (a MsgBox would hang it): it keeps the data unless
// run with /DELETEDATA=1
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  DataDir: String;
  DeleteData: Boolean;
begin
  if CurUninstallStep = usPostUninstall then
  begin
    DataDir := ExpandConstant('{commonappdata}\SingBoxTray');
    if DirExists(DataDir) then
    begin
      if UninstallSilent then
        DeleteData := ExpandConstant('{param:DELETEDATA|0}') = '1'
      else
        DeleteData := MsgBox('Удалить также настройки, подписки и логи?' + #13#10 + DataDir, mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES;
      if DeleteData then
        DelTree(DataDir, True, True, True);
    end;
  end;
end;
