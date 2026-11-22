; Inno Setup script for yanas net (Windows).
; Build the executables and the portable ZIP first (packaging\build-win.ps1),
; then compile this script with Inno Setup (iscc.exe packaging\yanas-net.iss).

#define MyAppName "yanas net"
#define MyAppVersion "0.1.0"
#define MyAppPublisher "yanas"

[Setup]
AppId={{6E2B6B3E-6B1F-4E2A-9C1D-9B0E6C7A1234}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\yanas net
DefaultGroupName={#MyAppName}
OutputDir=..\dist
OutputBaseFilename=yanas-net-{#MyAppVersion}-setup
Compression=lzma2
SolidCompression=yes
ArchitecturesAllowed=x64
ArchitecturesInstallIn64BitMode=x64

[Files]
Source: "..\yanasnet.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\netsim.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\LICENSE"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\THIRD_PARTY_NOTICES.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\docs\*"; DestDir: "{app}\docs"; Flags: recursesubdirs ignoreversion
Source: "..\web\*"; DestDir: "{app}\web"; Flags: recursesubdirs ignoreversion

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\yanasnet.exe"
Name: "{group}\{#MyAppName} CLI"; Filename: "{app}\netsim.exe"

[Run]
Filename: "{app}\yanasnet.exe"; Description: "Launch yanas net"; Flags: nowait postinstall skipifsilent
