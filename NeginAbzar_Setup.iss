#define MyAppName "حسابداری OMID PC"
#define MyAppVersion "5.5.4"
#define MyAppPublisher "OMID PC"
#define MyAppURL "https://www.omidpcservice.ir/"
#define MyAppExeName "OMIDPCLauncher.exe"

[Setup]
AppId={{D7F6C6B1-1C2E-4E3E-9F5C-123456789055}}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
SetupIconFile=omidpc.ico
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={autopf}\OMID PC Accounting
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
PrivilegesRequired=admin
CloseApplications=yes
RestartApplications=no
Uninstallable=yes
OutputDir=release
OutputBaseFilename=OMID-PC-Setup-v{#MyAppVersion}-OMIDPC
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
VersionInfoVersion=5.5.4.0
VersionInfoDescription=Installer for {#MyAppName}
VersionInfoProductName={#MyAppName}
VersionInfoCompany={#MyAppPublisher}
VersionInfoCopyright=Copyright {#MyAppPublisher}

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "ایجاد میانبر روی دسکتاپ"; GroupDescription: "میانبرها:"; Flags: unchecked
Name: "startmenuicon"; Description: "ایجاد میانبر در منوی Start"; GroupDescription: "میانبرها:"; Flags: checkedonce

[Files]
Source: "build_release\negin_abzar_v5.5.4_BACKUP_PRO.dist\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "NeginAbzar_Diagnostic.bat"; DestDir: "{app}"; Flags: ignoreversion
Source: "omidpc.ico"; DestDir: "{app}"; Flags: ignoreversion

[Dirs]
Name: "{localappdata}\OMIDPCAccounting"

[Icons]
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"; IconFilename: "{app}\OMIDPC_Accounting.exe"; Tasks: desktopicon
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"; IconFilename: "{app}\OMIDPC_Accounting.exe"; Tasks: startmenuicon
Name: "{group}\Uninstall {#MyAppName}"; Filename: "{uninstallexe}"
Name: "{group}\ابزار عیب‌یابی OMID PC"; Filename: "{app}\NeginAbzar_Diagnostic.bat"; WorkingDir: "{app}"

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "اجرای OMID PC"; Flags: nowait postinstall skipifsilent
