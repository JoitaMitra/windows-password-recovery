$ProviderName = "PasswordRecovery"
$ProviderGuid = "{749b22cd-f9fb-49bc-b5ad-cebcb4800a0d}"

$InstallDir = "$env:ProgramFiles\WindowsPasswordRecoveryProvider"
$DllPath = Join-Path $InstallDir "$ProviderName.dll"

Write-Host "Registering Credential Provider..."

# Credential Provider registration
New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\$ProviderGuid" -Force | Out-Null

Set-ItemProperty `
    -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\$ProviderGuid" `
    -Name "(Default)" `
    -Value $ProviderName

# CLSID registration
New-Item -Path "HKCR:\CLSID\$ProviderGuid" -Force | Out-Null

Set-ItemProperty `
    -Path "HKCR:\CLSID\$ProviderGuid" `
    -Name "(Default)" `
    -Value $ProviderName

New-Item -Path "HKCR:\CLSID\$ProviderGuid\InprocServer32" -Force | Out-Null

Set-ItemProperty `
    -Path "HKCR:\CLSID\$ProviderGuid\InprocServer32" `
    -Name "(Default)" `
    -Value $DllPath

Set-ItemProperty `
    -Path "HKCR:\CLSID\$ProviderGuid\InprocServer32" `
    -Name "ThreadingModel" `
    -Value "Apartment"

Write-Host "Credential Provider registered successfully."