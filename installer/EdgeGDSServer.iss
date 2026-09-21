; Inno Setup script for the Edge GDS Server Windows package.
; Build with (from the project root):
;   ISCC installer\EdgeGDSServer.iss
; Requires the PyInstaller build to already exist at dist\EdgeGDSServer\
; (see windows_service.spec / README's Windows packaging section).
;
; This is an ADDITION to the Docker/Linux deployment, not a replacement --
; it packages the same application code as a Windows Service for local
; testing on Windows 11, nothing here touches the Docker image or its build.
;
; Deliberately no autostart: the service is registered with Manual start
; and is never started by the installer. This tool is meant for testing,
; not for running unattended in production -- start/stop it yourself via
; Services, `net start`/`net stop`, or the Start Menu shortcuts below.

#define MyAppName "Edge GDS Server"
#define MyAppVersion "1.0.0"
#define MyAppPublisher "Edge GDS Server Project"
#define MyServiceName "EdgeGDSServer"
#define MyAppExeName "EdgeGDSServer.exe"

[Setup]
AppId={{6E2C5C0C-6F0E-4C1D-9C0B-2E7B7B7C5B10}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=..\dist_installer
OutputBaseFilename=EdgeGDSServer-Setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
UninstallDisplayIcon={app}\{#MyAppExeName}

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Files]
Source: "..\dist\EdgeGDSServer\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\installer\env.example"; DestDir: "{app}"; DestName: ".env.example"; Flags: ignoreversion

[Icons]
Name: "{group}\Web admin UI"; Filename: "https://localhost:8443/"; IconFilename: "{app}\{#MyAppExeName}"
Name: "{group}\Open data folder"; Filename: "{commonappdata}\{#MyAppName}"
Name: "{group}\Uninstall {#MyAppName}"; Filename: "{uninstallexe}"

[Dirs]
Name: "{commonappdata}\{#MyAppName}"

[Run]
; Register the Windows Service -- Manual start, never auto-started here.
Filename: "{app}\{#MyAppExeName}"; Parameters: "--startup=manual install"; \
    WorkingDir: "{app}"; StatusMsg: "Registering the Edge GDS Server service (manual start)..."; Flags: runhidden

; Open Windows Firewall for the OPC UA and web UI ports -- otherwise a
; fresh Windows 11 install will silently block incoming connections to
; both, and "it doesn't work" is a much worse first impression than one
; extra firewall rule.
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall add rule name=""Edge GDS Server (OPC UA)"" dir=in action=allow protocol=TCP localport=4840"; Flags: runhidden
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall add rule name=""Edge GDS Server (Web UI)"" dir=in action=allow protocol=TCP localport=8443"; Flags: runhidden

[UninstallRun]
Filename: "{app}\{#MyAppExeName}"; Parameters: "stop"; WorkingDir: "{app}"; Flags: runhidden; RunOnceId: "StopService"
Filename: "{app}\{#MyAppExeName}"; Parameters: "remove"; WorkingDir: "{app}"; Flags: runhidden; RunOnceId: "RemoveService"
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall delete rule name=""Edge GDS Server (OPC UA)"""; Flags: runhidden; RunOnceId: "RemoveFirewallOpcUa"
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall delete rule name=""Edge GDS Server (Web UI)"""; Flags: runhidden; RunOnceId: "RemoveFirewallWeb"

[UninstallDelete]
; Deliberately NOT deleting {commonappdata}\{#MyAppName} on uninstall --
; that's the CA private key and the certificate database, the same "treat
; it like a secrets store" data the Docker README calls out. An admin who
; wants it gone can delete C:\ProgramData\Edge GDS Server\ themselves.

[Code]
function InitializeSetup(): Boolean;
begin
  Result := True;
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  EnvPath: String;
  DataDir: String;
begin
  if CurStep = ssPostInstall then
  begin
    { Write a real .env only if one doesn't already exist -- an upgrade
      install should never clobber an admin's existing configuration. }
    EnvPath := ExpandConstant('{app}\.env');
    if not FileExists(EnvPath) then
    begin
      DataDir := ExpandConstant('{commonappdata}\{#MyAppName}\data');
      SaveStringToFile(EnvPath,
        '# Edge GDS Server configuration -- see .env.example for every option.' + #13#10 +
        'GDS_DATA_DIR=' + DataDir + #13#10 +
        'GDS_HOSTNAME=localhost' + #13#10,
        False);
    end;
  end;
end;
