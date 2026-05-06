[Setup]
AppName=Windows Password Recovery Provider
AppVersion=1.0.0
VersionInfoDescription=Windows Password Recovery Setup
VersionInfoVersion=1.0.0.0
VersionInfoCopyright=Copyright (C) 2026 Joita Mitra
VersionInfoProductName=
VersionInfoProductVersion=
VersionInfoProductTextVersion=
VersionInfoCompany=
DefaultDirName={autopf}\WindowsPasswordRecoveryProvider
DefaultGroupName=Windows Password Recovery Provider
OutputDir=output
OutputBaseFilename=windows-password-recovery
Compression=lzma
SolidCompression=yes
PrivilegesRequired=admin
WizardStyle=modern
ArchitecturesInstallIn64BitMode=x64compatible
RestartIfNeededByRun=yes

SetupIconFile=assets\icon.ico

[Code]

var
  DebugLoggingPage: TInputOptionWizardPage;

function EnableDebugLogging: Boolean;
begin
  Result := DebugLoggingPage.Values[0];
end;

procedure InitializeWizard;
begin
  DebugLoggingPage := CreateInputOptionPage(
    wpSelectTasks,
    'Logging Options',
    'Select Installer Options',
    'Choose whether to enable Credential Provider debug logging.',
    True,
    False
  );

  DebugLoggingPage.Add('Enable Debug Logging');
end;

[Files]
; Normal DLL
Source: "payload\PasswordRecovery.dll"; \
DestDir: "{app}"; \
DestName: "PasswordRecovery.dll"; \
Flags: ignoreversion; \
Check: not EnableDebugLogging

; Logging DLL
Source: "payload\PasswordRecovery_Debug.dll"; \
DestDir: "{app}"; \
DestName: "PasswordRecovery.dll"; \
Flags: ignoreversion; \
Check: EnableDebugLogging

; VC Runtime
Source: "payload\VC_redist.x64.exe"; \
DestDir: "{tmp}"; \
Flags: deleteafterinstall

; Scripts
Source: "scripts\register-cp.ps1"; \
DestDir: "{app}"; \
Flags: ignoreversion

Source: "scripts\unregister-cp.ps1"; \
DestDir: "{app}"; \
Flags: ignoreversion

[Run]
Filename: "{tmp}\VC_redist.x64.exe"; Parameters: "/quiet /norestart"; StatusMsg: "Installing VC++ Runtime..."; Flags: runhidden

Filename: "powershell.exe"; \
Parameters: "-ExecutionPolicy Bypass -File ""{app}\register-cp.ps1"""; \
StatusMsg: "Registering Credential Provider..."; \
Flags: runhidden

[UninstallRun]
Filename: "powershell.exe"; \
Parameters: "-ExecutionPolicy Bypass -File ""{app}\unregister-cp.ps1"""; \
Flags: runhidden; \
RunOnceId: "UnregisterCredentialProvider"

[Icons]
Name: "{group}\Uninstall Windows Password Recovery Provider"; Filename: "{uninstallexe}"