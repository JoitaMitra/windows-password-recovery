$ProviderGuid = "{749b22cd-f9fb-49bc-b5ad-cebcb4800a0d}"

Write-Host "Removing Credential Provider registration..."

Remove-Item `
    -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\$ProviderGuid" `
    -Recurse `
    -Force `
    -ErrorAction SilentlyContinue

Remove-Item `
    -Path "Registry::HKEY_CLASSES_ROOT\CLSID\$ProviderGuid" `
    -Recurse `
    -Force `
    -ErrorAction SilentlyContinue

Write-Host "Credential Provider unregistered."