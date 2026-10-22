; Windows installer (Inno Setup 6). Built by the Release workflow:
;   ISCC /DAppVersion=0.2.0 /DStage=<staged install directory> /O<output dir> packaging\velora.iss
; Installs per user, without administrator rights, into a directory the user can write to, so
; the app can keep updating itself. The lock screen service (Program Files) is managed by the
; app and is left alone on uninstall.

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

[UninstallDelete]
; Files the updater adds or leaves behind (new versions' files, renamed old executables).
Type: filesandordirs; Name: "{app}"
