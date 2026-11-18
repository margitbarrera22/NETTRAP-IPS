; Script de Inno Setup para generar NetTrap-IPS-Setup.exe
; Empaqueta toda la aplicación en un único instalador con servidor automático y acceso directo.

#define MyAppName "NetTrap-IPS"
#define MyAppVersion "3.2.0"
#define MyAppPublisher "Equipo CyberDefender (UNIPAZ)"
#define MyAppExeName "NetTrap-IPS.exe"

[Setup]
AppId={{7B6E8C21-5E34-4B9E-A3D1-9C4F10E2A320}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
AllowNoIcons=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=..\dist
OutputBaseFilename=NetTrap-IPS-Setup
SetupIconFile=nettrap.ico
UninstallDisplayIcon={app}\{#MyAppExeName}
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
CloseApplications=yes
AppMutex=Local\NetTrapIPS_SingleInstance_Mutex

[Languages]
Name: "spanish"; MessagesFile: "compiler:Languages\Spanish.isl"

[Tasks]
Name: "desktopicon"; Description: "Crear un acceso directo en el &Escritorio"; GroupDescription: "Accesos directos:"
Name: "autostart"; Description: "Mantener el servidor activo automáticamente al iniciar Windows (sin consola ni comandos)"; GroupDescription: "Servidor en segundo plano:"

[Dirs]
Name: "{commonappdata}\NetTrap-IPS\data\logs"; Permissions: users-modify
Name: "{commonappdata}\NetTrap-IPS\data\pcap"; Permissions: users-modify

[Files]
Source: "..\dist\NetTrap-IPS\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\Manual_1_Instalacion_NetTrap.pdf"; DestDir: "{app}\Manuales"; Flags: ignoreversion
Source: "..\Manual_2_Uso_NetTrap.pdf"; DestDir: "{app}\Manuales"; Flags: ignoreversion
Source: "..\Manual_3_Funcionamiento_NetTrap.pdf"; DestDir: "{app}\Manuales"; Flags: ignoreversion

[Icons]
Name: "{group}\{#MyAppName} SOC"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\Carpeta de Evidencias (.pcap y logs)"; Filename: "{commonappdata}\NetTrap-IPS\data"
Name: "{group}\Manuales de {#MyAppName}"; Filename: "{app}\Manuales"
Name: "{group}\Desinstalar {#MyAppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName} SOC"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "schtasks.exe"; Parameters: "/Create /TN ""NetTrap-IPS Server"" /TR ""\""{app}\{#MyAppExeName}\"" --autostart"" /SC ONLOGON /RL HIGHEST /F"; Flags: runhidden waituntilterminated; Tasks: autostart
Filename: "{app}\{#MyAppExeName}"; Description: "Iniciar servidor NetTrap-IPS y abrir el Dashboard SOC ahora"; Flags: nowait postinstall skipifsilent

[UninstallRun]
Filename: "taskkill.exe"; Parameters: "/F /IM {#MyAppExeName}"; Flags: runhidden waituntilterminated; RunOnceId: "KillNetTrap"
Filename: "schtasks.exe"; Parameters: "/Delete /TN ""NetTrap-IPS Server"" /F"; Flags: runhidden waituntilterminated; RunOnceId: "DelNetTrapTask"
Filename: "netsh.exe"; Parameters: "advfirewall firewall delete rule name=""NetTrap-Inbound-SOC"""; Flags: runhidden waituntilterminated; RunOnceId: "DelFwSoc"
Filename: "netsh.exe"; Parameters: "advfirewall firewall delete rule name=""NetTrap-Inbound-ICMP"""; Flags: runhidden waituntilterminated; RunOnceId: "DelFwIcmp"

[Code]
function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  ResultCode: Integer;
begin
  Exec('taskkill.exe', '/F /IM NetTrap-IPS.exe', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Result := '';
end;
