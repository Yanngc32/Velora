; Windows installer (Inno Setup 6). Built by the Release workflow:
;   ISCC /DAppVersion=0.2.0 /DStage=<staged install directory> /O<output dir> packaging\velora.iss
; Installs per user, without administrator rights, into a directory the user can write to, so
; the app can keep updating itself. The lock screen service (Program Files) is managed by the
; app and is left alone on uninstall. The firewall rule for the host needs administrator
; rights: it is added and removed behind a UAC prompt (see [Code]).

#ifndef AppVersion
  #error Pass /DAppVersion=<version>
#endif
#ifndef Stage
  #error Pass /DStage=<staged install directory>
#endif

[Setup]
AppId={{1DE117D0-3A96-4B8D-A311-96FFF32CD0AC}
AppName=Velora
AppVersion={#AppVersion}
AppPublisher=Velora
AppPublisherURL=https://github.com/Yanngc32/Velora
AppSupportURL=https://github.com/Yanngc32/Velora/issues
AppUpdatesURL=https://github.com/Yanngc32/Velora/releases
DefaultDirName={localappdata}\Programs\Velora
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
CloseApplications=yes
RestartApplications=no
WizardStyle=modern
SetupIconFile=velora.ico
UninstallDisplayIcon={app}\velora.ico
UninstallDisplayName=Velora
OutputBaseFilename=velora-{#AppVersion}-x86_64-pc-windows-msvc-setup
Compression=lzma2/max
SolidCompression=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"
Name: "brazilianportuguese"; MessagesFile: "compiler:Languages\BrazilianPortuguese.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "{#Stage}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "velora.ico"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\Velora"; Filename: "{app}\velora.exe"; IconFilename: "{app}\velora.ico"
Name: "{autodesktop}\Velora"; Filename: "{app}\velora.exe"; IconFilename: "{app}\velora.ico"; Tasks: desktopicon

[Registry]
; "Start with Windows" (crates/client/src/autostart.rs): only removed on uninstall, never created.
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: none; ValueName: "Velora"; Flags: uninsdeletevalue dontcreatekey

[Run]
Filename: "{app}\velora.exe"; Description: "{cm:LaunchProgram,Velora}"; Flags: nowait postinstall skipifsilent

[Code]
const
  FirewallRule = 'Velora';
  HostPort = '7420';

function Netsh(const Args: String): String;
begin
  Result := '"' + ExpandConstant('{sys}\netsh.exe') + '" advfirewall firewall ' + Args;
end;

{ Runs the commands elevated, behind a single UAC prompt. Declining it leaves the app
  installed; only other devices can't reach this PC on networks Windows did not allow. }
procedure RunElevated(const Commands: String);
var
  ResultCode: Integer;
begin
  { cmd strips the outer quotes and keeps the quoted paths inside. }
  if not ShellExec('runas', ExpandConstant('{cmd}'), '/c "' + Commands + '"', '', SW_HIDE,
    ewWaitUntilTerminated, ResultCode) then
    Log('Firewall rule not changed: ' + SysErrorMessage(ResultCode));
end;

{ Lets other devices reach the host on any network, Public included (the Windows prompt
  allows only Private networks). Rules Windows created for the host are removed first:
  a block rule from that prompt would win over this one. }
procedure CurStepChanged(CurStep: TSetupStep);
var
  Host: String;
begin
  if CurStep = ssPostInstall then
  begin
    Host := ExpandConstant('{app}\velora-host.exe');
    RunElevated(Netsh('delete rule name=all program="' + Host + '"') + ' & ' +
      Netsh('add rule name="' + FirewallRule + '" dir=in action=allow program="' + Host +
        '" protocol=UDP localport=' + HostPort + ' profile=any enable=yes'));
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usUninstall then
    RunElevated(Netsh('delete rule name="' + FirewallRule + '"'));
end;

[UninstallDelete]
; Files the updater adds or leaves behind (new versions' files, renamed old executables).
Type: filesandordirs; Name: "{app}"
; Send To entry the app adds when it starts (see crates/client/src/send_to.rs).
Type: files; Name: "{usersendto}\Velora.lnk"
