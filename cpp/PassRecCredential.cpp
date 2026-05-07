
#ifndef WIN32_NO_STATUS
#include <ntstatus.h>
#define WIN32_NO_STATUS
#endif
#include <unknwn.h>
#include "PassRecCredential.h"
#include "guid.h"
#include <lm.h>
#include <string>
#include <algorithm>
#include <fstream>
#include <sstream>
#include <ctime>
#include <windows.h>
#include <strsafe.h>
#include <time.h>
#include "common.h"
#include "helpers.h"

// Required libraries for credential UI, security APIs, and registry access
#pragma comment(lib, "Secur32.lib")
#pragma comment(lib, "Credui.lib") 
#pragma comment(lib, "Advapi32.lib")

typedef int (WINAPI* MessageBoxTimeoutW_t) (HWND, LPCWSTR, LPCWSTR, UINT, WORD, DWORD); // Prototype for MessageBoxTimeoutW

// Logger function
void LogToFile(const std::wstring& message)
{
    const wchar_t* logPath = L"C:\\ProgramData\\PasswordRecovery\\passreccp.log";

    // Create directory if needed
    CreateDirectoryW(L"C:\\ProgramData\\PasswordRecovery", nullptr);

    // Get current local timestamp
    SYSTEMTIME st;
    GetLocalTime(&st);

    std::wstringstream logStream;
    logStream << L"[" << st.wYear << L"-" << st.wMonth << L"-" << st.wDay
        << L" " << st.wHour << L":" << st.wMinute << L":" << st.wSecond << L"] "
        << message << L"\n";

    // Append to file
    FILE* file = nullptr;
    _wfopen_s(&file, logPath, L"a+, ccs=UTF-8");
    if (file)
    {
        fputws(logStream.str().c_str(), file);
        fclose(file);
    }
}

// Function to Write Status to Registry
static void WritetoRegistry(LPCWSTR subkeyName, LPCWSTR username, LPCWSTR status, int result, bool incrementCount = true)
{
    HKEY hBaseKey = nullptr;
    HKEY hSubKey = nullptr;
    SYSTEMTIME st;
    WCHAR dateTimeStr[100];

    LPCWSTR basePath = L"SOFTWARE\\PasswordRecovery";

    GetLocalTime(&st);
    swprintf_s(dateTimeStr, 100, L"%02d-%02d-%04d %02d:%02d:%02d", st.wDay, st.wMonth, st.wYear, st.wHour, st.wMinute, st.wSecond);

    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, basePath, 0, nullptr, 0, KEY_READ | KEY_WRITE, nullptr, &hBaseKey, nullptr) != ERROR_SUCCESS) //create base reg path
        return;

    if (RegCreateKeyExW(hBaseKey, subkeyName, 0, nullptr, 0, KEY_READ | KEY_WRITE, nullptr, &hSubKey, nullptr) != ERROR_SUCCESS) { //create subkey
        RegCloseKey(hBaseKey);
        return;
    }

    // set reg values
    RegSetValueExW(hSubKey, L"DateTime", 0, REG_SZ, (const BYTE*)dateTimeStr, (DWORD)((wcslen(dateTimeStr) + 1) * sizeof(WCHAR)));
    RegSetValueExW(hSubKey, L"Status", 0, REG_SZ, (const BYTE*)status, (DWORD)((wcslen(status) + 1) * sizeof(WCHAR)));
    RegSetValueExW(hSubKey, L"Result", 0, REG_DWORD, (const BYTE*)&result, sizeof(DWORD));
    RegSetValueExW(hSubKey, L"UserName", 0, REG_SZ, (const BYTE*)username, (DWORD)((wcslen(username) + 1) * sizeof(WCHAR)));

    if (incrementCount) // usage counter
    {
        DWORD count = 0;
        DWORD size = sizeof(count);
        DWORD type = REG_DWORD;

        LONG reg = RegQueryValueExW(hSubKey, L"Count", nullptr, &type, (LPBYTE)&count, &size);

        WCHAR buf[256];
        swprintf_s(buf, 256, L"[Registry] Reading Count from registry: result=%ld, type=%lu, count=%lu", reg, type, count);
        LOG(buf);

        if (reg == ERROR_SUCCESS && type == REG_DWORD) {
            count++;
        }
        else {
            count = 1; // initialize counter if missing
            LOG(L"[Registry] Count value not found or wrong type, resetting to 1.");
        }

        RegSetValueExW(hSubKey, L"Count", 0, REG_DWORD, (const BYTE*)&count, sizeof(DWORD));
    }
    RegCloseKey(hSubKey);
    RegCloseKey(hBaseKey);
}

// Function to execute a PowerShell command and returns output
std::wstring RunPowerShellCommand(const std::wstring& command)
{
    LOG(L"[Powershell] Executing command to retrieve recovery key");

    HANDLE hRead = NULL, hWrite = NULL;
    SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };

    if (!CreatePipe(&hRead, &hWrite, &sa, 0)) { // create pipe to capture child process output
        LOG(L"[Powershell] CreatePipe failed");
        return L"";
    }

    STARTUPINFOW si = { sizeof(si) };
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = hWrite;
    si.hStdError = hWrite;

    PROCESS_INFORMATION pi = { 0 };
    wchar_t cmdLine[1024];
    wcscpy_s(cmdLine, command.c_str());

    // launch PowerShell
    if (!CreateProcessW(NULL, cmdLine, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        DWORD err = GetLastError();
        LOG(L"[Powershell] CreateProcess failed. Code: " + std::to_wstring(err));
        CloseHandle(hRead);
        CloseHandle(hWrite);
        return L"";
    }
    CloseHandle(hWrite);

    CHAR buffer[512] = {};
    DWORD bytesRead;
    std::string output;

    // read output till process closes pipe
    while (ReadFile(hRead, buffer, sizeof(buffer) - 1, &bytesRead, NULL) && bytesRead != 0) {
        buffer[bytesRead] = '\0';
        output += buffer;
    }

    CloseHandle(hRead);
    DWORD waitResult = WaitForSingleObject(pi.hProcess, 5000); // wait time of 5 seconds to avaoid blocking logon
    if (waitResult == WAIT_TIMEOUT)
    {
        LOG(L"[Powershell] Powershell command timed out after 5 seconds. Terminating process.");
        TerminateProcess(pi.hProcess, 1);
    }
    else if (waitResult != WAIT_OBJECT_0)
    {
        LOG(L"[Powershell] WaitForSingleObject failed. Code: " + std::to_wstring(GetLastError()));
    }
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    // Normalize output by removing line break characters
    output.erase(std::remove(output.begin(), output.end(), '\n'), output.end());
    output.erase(std::remove(output.begin(), output.end(), '\r'), output.end());

    std::wstring woutput(output.begin(), output.end());

    if (woutput.empty()) {
        LOG(L"[Powershell] Powershell produced no output.");
    }
    else {
        LOG(L"[Powershell] Powershell Output: " + woutput);
    }

    return woutput;
}

// Function to detect Domain joined machines
bool IsMachineDomainJoined()
{
    ////------------TEST OVERRIDE FOR DOMAIN---------------
    //HKEY hKey;
    //DWORD overrideValue = 0;
    //DWORD size = sizeof(overrideValue);
    //if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\PasswordRecovery", 0, KEY_READ, &hKey) == ERROR_SUCCESS)
    //{
    //    if (RegQueryValueExW(hKey, L"DomainJoinOverride", nullptr, nullptr, (LPBYTE)&overrideValue, &size) == ERROR_SUCCESS)
    //    {
    //        RegCloseKey(hKey);
    //        if (overrideValue == 1)
    //        {
    //            LOG(L"[DomainCheck] DomainJoinOverride ENABLED -> treating device as domain joined.");
    //            return true;
    //        }
    //    }
    //    RegCloseKey(hKey);
    //}

    LPWSTR domainName = NULL;
    NETSETUP_JOIN_STATUS status;

    DWORD dw = NetGetJoinInformation(NULL, &domainName, &status);

    if (domainName)
        NetApiBufferFree(domainName);

    return (dw == NERR_Success && status == NetSetupDomainName);
}

// Function to attempt logon using known password "TempP@ss123" to check if user has changed it or not
bool IsTempPasswordStillSet(PCWSTR pszQualifiedUserName)
{
    WCHAR buf[512];
    swprintf_s(buf, L"[PasswordCheck] Testing if password is still TempP@ss123 for user: %s", pszQualifiedUserName ? pszQualifiedUserName : L"(null)");
    LOG(buf);

    bool stillSet = false;
    PWSTR pszDomain = nullptr;
    PWSTR pszUsername = nullptr;

    // required context for LSA logon attempt
    TOKEN_SOURCE sourceContext = { "CP", {0,0} };
    AllocateLocallyUniqueId(&sourceContext.SourceIdentifier);

    LSA_STRING originName;
    _LsaInitString(&originName, "CP");

    PVOID profileBuffer = nullptr;
    ULONG profileBufferLen = 0;
    LUID logonId = {};
    HANDLE token = nullptr;
    QUOTA_LIMITS quotas;
    NTSTATUS subStatus = 0;

    BYTE* rgbPacked = nullptr;
    DWORD cbPacked = 0;

    // validate input to avoid invalid LSA calls
    if (!pszQualifiedUserName || *pszQualifiedUserName == L'\0')
    {
        LOG(L"[PasswordCheck] pszQualifiedUserName is NULL or empty. Aborting password check.");
        return false;
    }

    // split DOMAIN\Username structure
    HRESULT hr = SplitDomainAndUsername(pszQualifiedUserName, &pszDomain, &pszUsername);
    if (FAILED(hr))
    {
        swprintf_s(buf, L"[PasswordCheck] SplitDomainAndUsername FAILED hr=0x%08X", hr);
        LOG(buf);
        return false;
    }
    swprintf_s(buf, L"[PasswordCheck] SplitDomainAndUsername -> %s\\%s", pszDomain, pszUsername);
    LOG(buf);

    // Initialize Kerberos interactive logon using the known reset password
    KERB_INTERACTIVE_UNLOCK_LOGON kiul;
    hr = KerbInteractiveUnlockLogonInit(pszDomain, pszUsername, L"TempP@ss123", CPUS_LOGON, &kiul);
    if (FAILED(hr))
    {
        swprintf_s(buf, L"[PasswordCheck] KerbInteractiveUnlockLogonInit FAILED hr=0x%08X", hr);
        LOG(buf);
        goto Cleanup;
    }
    LOG(L"[PasswordCheck] KerbInteractiveUnlockLogonInit succeeded");

    // Pack the logon structure for LSA consumption
    hr = KerbInteractiveUnlockLogonPack(kiul, &rgbPacked, &cbPacked);
    if (FAILED(hr))
    {
        swprintf_s(buf, L"[PasswordCheck] KerbInteractiveUnlockLogonPack FAILED hr=0x%08X", hr);
        LOG(buf);
        goto Cleanup;
    }
    swprintf_s(buf, L"[PasswordCheck] KerbInteractiveUnlockLogonPack succeeded, size=%lu", cbPacked);
    LOG(buf);

    // Retrieve the Negotiate authentication package ID
    ULONG authPackage = 0;
    hr = RetrieveNegotiateAuthPackage(&authPackage);
    if (FAILED(hr))
    {
        swprintf_s(buf, L"[PasswordCheck] RetrieveNegotiateAuthPackage FAILED hr=0x%08X", hr);
        LOG(buf);
        goto Cleanup;
    }
    swprintf_s(buf, L"[PasswordCheck] RetrieveNegotiateAuthPackage succeeded, package=%lu", authPackage);
    LOG(buf);

    // Connect to LSA without registering as a logon process
    HANDLE hLsa = nullptr;
    NTSTATUS status = LsaConnectUntrusted(&hLsa);
    if (status < 0)
    {
        swprintf_s(buf, L"[PasswordCheck] LsaConnectUntrusted FAILED status=0x%08X", status);
        LOG(buf);
        goto Cleanup;
    }
    LOG(L"[PasswordCheck] LsaConnectUntrusted succeeded");

    // Attempt logon using the known password
    status = LsaLogonUser(
        hLsa,
        &originName,
        Interactive,
        authPackage,
        rgbPacked,
        cbPacked,
        nullptr,
        &sourceContext,
        &profileBuffer,
        &profileBufferLen,
        &logonId,
        &token,
        &quotas,
        &subStatus
    );
    swprintf_s(buf, L"[PasswordCheck] LsaLogonUser returned status=0x%08X subStatus=0x%08X", status, subStatus);
    LOG(buf);
    
    // Treat certain failure statuses as password match: Password expired, Password must change - indicate supplied password was correct 
    bool passwordMatches =
        (status >= 0) ||
        (status == (NTSTATUS)0xC0000224L) || // STATUS_PASSWORD_MUST_CHANGE
        (status == (NTSTATUS)0xC0000071L) || // STATUS_PASSWORD_EXPIRED
        ((status == (NTSTATUS)0xC000006EL) &&  // STATUS_ACCOUNT_RESTRICTION
        (subStatus == (NTSTATUS)0xC0000224L || subStatus == (NTSTATUS)0xC0000071L));

    if (passwordMatches)
    {
        stillSet = true;
        CloseHandle(token);
        LOG(L"[PasswordCheck] TempP@ss123 password IS still valid.");
    }
    else
    {
        LOG(L"[PasswordCheck] TempP@ss123 password is NOT valid or logon failed.");
    }

    if (profileBuffer)
        LsaFreeReturnBuffer(profileBuffer);

    LsaDeregisterLogonProcess(hLsa);

Cleanup:
    if (pszDomain) CoTaskMemFree(pszDomain);
    if (pszUsername) CoTaskMemFree(pszUsername);
    if (rgbPacked) CoTaskMemFree(rgbPacked);

    return stillSet;
}

// Reads BitLocker recovery key from keys.cache file as fallback mechanism
std::wstring ReadKeyFromCacheFile(const std::wstring& path)
{
    FILE* file = nullptr;
    _wfopen_s(&file, path.c_str(), L"r");

    if (!file) {
        LOG(L"[Fallback] Could not open keys.cache at : " + path);
        return L""; 
    }

    LOG(L"[Fallback] Opened keys.cache successfully.");
    WCHAR line[512];
    WCHAR expectedKeyRaw[256] = { 0 };
    bool keyFound = false;

    // Scan file line by line to locate recoveryKey
    while (fgetws(line, ARRAYSIZE(line), file))
    {
        if (wcsstr(line, L"recoveryKey"))
        {
            WCHAR* colon = wcschr(line, L':');
            if (!colon) continue;

            WCHAR* start = wcschr(colon, L'"');
            if (!start) continue;
            start++;

            WCHAR* end = wcschr(start, L'"');
            if (!end) continue;
            *end = L'\0';

            wcscpy_s(expectedKeyRaw, start);
            keyFound = true;
            break;
        }
    }
    fclose(file);

    if (!keyFound) {
        LOG(L"[Fallback] Did not find 'recoveryKey' in keys.cache.");
        return L"";
    }

    std::wstring key(expectedKeyRaw);
    LOG(L"[Fallback] Recovery Key extracted: " + key);

    // Saving recovery key source as cache file in registry
    RegSetKeyValueW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\PasswordRecovery\\credential-provider-reset",
        L"RecoveryKeySource", REG_SZ,
        L"CacheFile", (DWORD)((wcslen(L"CacheFile") + 1) * sizeof(WCHAR)));
    return key;
}

// Retrieves BitLocker recovery key using Powershell command Get-BitLockerVolume
std::wstring GetBitlockerRecoveryKey()
{
    std::wstring command = L"powershell.exe -NoProfile -Command \""
        L"$vol = Get-BitLockerVolume -MountPoint C; "
        L"$rec = $vol.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' }; "
        L"if ($rec) { $rec.RecoveryPassword }\"";

    LOG(L"[BitLocker] Attempting to retrieve BitLocker Recovery Key via Powershell.");
    std::wstring recoveryKey = RunPowerShellCommand(command);

    // detect powershell error output
    if (recoveryKey.find(L"CategoryInfo") != std::wstring::npos ||
        recoveryKey.find(L"FullyQualifiedErrorId") != std::wstring::npos) {
        LOG(L"[BitLocker] PowerShell returned an error instead of a key: " + recoveryKey);
        recoveryKey.clear();
    }

    if (!recoveryKey.empty()) {
        // save recovery key source as powershell in registry
        RegSetKeyValueW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\PasswordRecovery\\credential-provider-reset",
            L"RecoveryKeySource", REG_SZ,
            L"PowerShell", (DWORD)((wcslen(L"PowerShell") + 1) * sizeof(WCHAR)));

        // recovery keys are always 48 digits + 7 dashes = 55 characters
        if (recoveryKey.length() != 55) {
            LOG(L"[BitLocker] Recovery key length invalid: " + recoveryKey);
            recoveryKey.clear();
        }
        else {
            bool valid = true;
            for (size_t i = 0; i < recoveryKey.length(); ++i) {
                if ((i + 1) % 7 == 0) {
                    if (recoveryKey[i] != L'-') { valid = false; break; }
                }
                else {
                    if (!iswdigit(recoveryKey[i])) { valid = false; break; }
                }
            }
            if (!valid) {
                LOG(L"[BitLocker] Recovery key format invalid: " + recoveryKey);
                recoveryKey.clear();
            }
        }
    }

    // Fallback to cache file if powershell retrieval fails
    //if (recoveryKey.empty()) {
    //    LOG(L"[BitLocker] Powershell retrieval failed. Trying keys.cache fallback.");
    //    recoveryKey = ReadKeyFromCacheFile(L"C:\\ProgramData\\config\\keys.cache");
    //}

    if (recoveryKey.empty()) {
        LOG(L"[BitLocker] No recovery key retrieved.");
    }

    return recoveryKey;
}

PassRecCredential::PassRecCredential():
    _cRef(1),
    _cpus(CPUS_INVALID),
    _pCredProvCredentialEvents(nullptr),
    _pszUserSid(nullptr),
    _pszQualifiedUserName(nullptr),
    _fPinChecked(false),
    _fBitlockerChecked(false),
    _fUnexpirationDisabled(false)
{
    LOG(L"[Credential] Constructor called");
    DllAddRef();

    ZeroMemory(_rgCredProvFieldDescriptors, sizeof(_rgCredProvFieldDescriptors));
    ZeroMemory(_rgFieldStatePairs, sizeof(_rgFieldStatePairs));
    ZeroMemory(_rgFieldStrings, sizeof(_rgFieldStrings));
}

PassRecCredential::~PassRecCredential()
{
    LOG(L"[Credential] Destructor called");
    // Securely clear sesnsitive BitLocker key input before releasing memory
    if (_rgFieldStrings[SFI_BITLOCKER_KEY])
    {
        size_t lenBitlocker = wcslen(_rgFieldStrings[SFI_BITLOCKER_KEY]);
        SecureZeroMemory(_rgFieldStrings[SFI_BITLOCKER_KEY], lenBitlocker * sizeof(*_rgFieldStrings[SFI_BITLOCKER_KEY]));
    }
    for (int i = 0; i < ARRAYSIZE(_rgFieldStrings); i++)
    {
        CoTaskMemFree(_rgFieldStrings[i]);
        CoTaskMemFree(_rgCredProvFieldDescriptors[i].pszLabel);
    }
    CoTaskMemFree(_pszUserSid);
    CoTaskMemFree(_pszQualifiedUserName);
    DllRelease();
}


HRESULT PassRecCredential::Initialize(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
                                      _In_ CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR const *rgcpfd,
                                      _In_ FIELD_STATE_PAIR const *rgfsp,
                                      _In_ ICredentialProviderUser *pcpUser)
{
    LOG(L"[Credential] Initialization started");
    HRESULT hr = S_OK;
    _cpus = cpus;

    GUID guidProvider;
    pcpUser->GetProviderID(&guidProvider);
    _fUnexpirationDisabled = false;

    // Copy field descriptors and state configuration from provider
    for (DWORD i = 0; SUCCEEDED(hr) && i < ARRAYSIZE(_rgCredProvFieldDescriptors); i++)
    {
        _rgFieldStatePairs[i] = rgfsp[i];
        hr = FieldDescriptorCopy(rgcpfd[i], &_rgCredProvFieldDescriptors[i]);
    }

    // Initialize the String UI text of all the fields.
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"Password Recovery Options", &_rgFieldStrings[SFI_LARGE_TEXT]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"I remember my PIN. Sign in and change Password using Windows Hello PIN", &_rgFieldStrings[SFI_PIN_CHECKBOX]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"Confirm", &_rgFieldStrings[SFI_SUBMIT_PIN]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"", &_rgFieldStrings[SFI_PIN_HINT_TEXT]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"Reset Password using BitLocker Recovery Key", &_rgFieldStrings[SFI_BITLOCKER_CHECKBOX]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"", &_rgFieldStrings[SFI_BITLOCKER_KEY]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"Submit", &_rgFieldStrings[SFI_SUBMIT_BUTTON]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"Where to find my BitLocker key?", &_rgFieldStrings[SFI_HELPWINDOW_LINK]);
    }
    /*if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"", &_rgFieldStrings[SFI_PASSWORD_INFO_TEXT]);
    }*/

    // Get user identity information
    if (SUCCEEDED(hr))
    {
        hr = pcpUser->GetStringValue(PKEY_Identity_QualifiedUserName, &_pszQualifiedUserName);
        if (SUCCEEDED(hr) && _pszQualifiedUserName != nullptr)
        {
            LOG(L"[Credential] Set _pszQualifiedUserName to: " + std::wstring(_pszQualifiedUserName));
        }
        else {
            LOG(L"[Credential] Failed to get QualifiedUserName from ICredentialProviderUser or it was null.");
        }
    }
    if (SUCCEEDED(hr))
    {
        hr = pcpUser->GetSid(&_pszUserSid);
        if (SUCCEEDED(hr) && _pszUserSid != nullptr)
        {
            LOG(L"[Credential] Set _pszUserSid to: " + std::wstring(_pszUserSid));
        }
        else {
            LOG(L"[Credential] Failed to get SID from ICredentialProviderUser or it was null.");
        }
    }

    if (FAILED(hr)) {
        LOG(L"[Credential] Initialize failed with HRESULT: " + std::to_wstring(hr));
    }
    return hr;
}

// LogonUI calls this in order to give us a callback in case we need to notify it of anything.
HRESULT PassRecCredential::Advise(_In_ ICredentialProviderCredentialEvents* pcpce) {

    if (_pCredProvCredentialEvents != nullptr) {

        _pCredProvCredentialEvents->Release();

    }
    
    return pcpce->QueryInterface(IID_PPV_ARGS(&_pCredProvCredentialEvents));
}

// LogonUI calls this to tell us to release the callback.
HRESULT PassRecCredential::UnAdvise()
{
    if (_pCredProvCredentialEvents)
    {
        _pCredProvCredentialEvents->Release();
    }
    _pCredProvCredentialEvents = nullptr;
    return S_OK;
}

// LogonUI calls this function when our tile is selected (zoomed)
// If you simply want fields to show/hide based on the selected state,
// there's no need to do anything here - you can set that up in the
// field definitions. But if you want to do something
// more complicated, like change the contents of a field when the tile is
// selected, you would do it here.
HRESULT PassRecCredential::SetSelected(_Out_ BOOL *pbAutoLogon)
{
    LOG(L"[Credential] SetSelected called");
    LOG(L"[DomainCheck] Checking if machine is domain joined.");

    // Disabling recovery options for domain joined devices
    if (IsMachineDomainJoined())
    {
        LOG(L"[DomainCheck] Device is domain joined. Disabling password recovery options.");

        if (_pCredProvCredentialEvents)
        {
            _pCredProvCredentialEvents->BeginFieldUpdates();
            _pCredProvCredentialEvents->SetFieldState(this, SFI_PIN_CHECKBOX, CPFS_HIDDEN);
            _pCredProvCredentialEvents->SetFieldState(this, SFI_BITLOCKER_CHECKBOX, CPFS_HIDDEN);
            _pCredProvCredentialEvents->SetFieldState(this, SFI_SUBMIT_PIN, CPFS_HIDDEN);
            _pCredProvCredentialEvents->SetFieldState(this, SFI_BITLOCKER_KEY, CPFS_HIDDEN);
            _pCredProvCredentialEvents->SetFieldState(this, SFI_SUBMIT_BUTTON, CPFS_HIDDEN);
            _pCredProvCredentialEvents->SetFieldState(this, SFI_HELPWINDOW_LINK, CPFS_HIDDEN);

            _pCredProvCredentialEvents->SetFieldString(this, SFI_LARGE_TEXT, L"Password Recovery options are disabled because this device is joined to a domain.");
            _pCredProvCredentialEvents->EndFieldUpdates();
        }
    }
    *pbAutoLogon = FALSE; // Prevent automatic logon when tile is selected

    //UpdatePasswordInfo();

    return S_OK;
}

// Similarly to SetSelected, LogonUI calls this when your tile was selected
// and now no longer is. 
// Used to clear sensitive user input
HRESULT PassRecCredential::SetDeselected()
{
    LOG(L"[Credential] SetDeselected called");
    HRESULT hr = S_OK;
    if (_rgFieldStrings[SFI_BITLOCKER_KEY])
    {
        // Clear BitLocker key before releasing memory
        size_t lenBitlocker = wcslen(_rgFieldStrings[SFI_BITLOCKER_KEY]);
        SecureZeroMemory(_rgFieldStrings[SFI_BITLOCKER_KEY], lenBitlocker * sizeof(*_rgFieldStrings[SFI_BITLOCKER_KEY]));

        CoTaskMemFree(_rgFieldStrings[SFI_BITLOCKER_KEY]);
        hr = SHStrDupW(L"", &_rgFieldStrings[SFI_BITLOCKER_KEY]);

        // Pushing cleared value back to UI
        if(SUCCEEDED(hr) && _pCredProvCredentialEvents)
        {
            _pCredProvCredentialEvents->SetFieldString(this, SFI_BITLOCKER_KEY, _rgFieldStrings[SFI_BITLOCKER_KEY]);
        }
    }
    return hr;
}

// Get info for a particular field of a tile. Called by logonUI to get information
// to display the tile.
HRESULT PassRecCredential::GetFieldState(DWORD dwFieldID,
    _Out_ CREDENTIAL_PROVIDER_FIELD_STATE *pcpfs,
    _Out_ CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE *pcpfis)
{
    HRESULT hr;

    // Validate our parameters.
    if ((dwFieldID < ARRAYSIZE(_rgFieldStatePairs)))
    {
        *pcpfs = _rgFieldStatePairs[dwFieldID].cpfs;
        *pcpfis = _rgFieldStatePairs[dwFieldID].cpfis;
        hr = S_OK;
    }
    else
        {
        hr = E_INVALIDARG;
    }
    return hr;
}


// Sets ppwsz to the string value of the field at the index dwFieldID
HRESULT PassRecCredential::GetStringValue(DWORD dwFieldID, _Outptr_result_nullonfailure_ PWSTR *ppwsz)
{
    HRESULT hr;
    *ppwsz = nullptr;

    // Check to make sure dwFieldID is a legitimate index
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors))
    {
        // Make a copy of the string and return that. The caller
        // is responsible for freeing it.
        hr = SHStrDupW(_rgFieldStrings[dwFieldID], ppwsz);
    }
    /*else if (dwFieldID == SFI_PASSWORD_INFO_TEXT)
    {
        *ppwsz = (PWSTR)::CoTaskMemAlloc(sizeof(wchar_t) * (1));
        if (*ppwsz)
            **ppwsz = L'\0';
        return S_OK;
    }*/
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Get the image to show in the user tile
HRESULT PassRecCredential::GetBitmapValue(DWORD dwFieldID, _Outptr_result_nullonfailure_ HBITMAP *phbmp)
{
    HRESULT hr;
    *phbmp = nullptr;

    if (dwFieldID == SFI_TILEIMAGE)
    {
        HBITMAP hbmp = LoadBitmap(HINST_THISDLL, MAKEINTRESOURCE(IDB_TILE_IMAGE));
       if (hbmp != nullptr)
       {
             *phbmp = hbmp;
             hr = S_OK;
        }
        else
        {
           DWORD err = GetLastError();
           LOG((L"[Credential] Failed to load bitmap. Error: " + std::to_wstring(err)).c_str());
           hr = HRESULT_FROM_WIN32(err);
        }
     }
     else
     {
         hr = E_INVALIDARG;
     }

    return hr;
}

// Sets pdwAdjacentTo to the index of the field the submit button should be
// adjacent to. We recommend that the submit button is placed next to the last
// field which the user is required to enter information in. Optional fields
// should be below the submit button.
HRESULT PassRecCredential::GetSubmitButtonValue(DWORD dwFieldID, _Out_ DWORD *pdwAdjacentTo)
{
    HRESULT hr;

    if (SFI_SUBMIT_BUTTON == dwFieldID)
    {
        // submit button appears next to the BitLocker key input field
        *pdwAdjacentTo = SFI_BITLOCKER_KEY;
        hr = S_OK;
    }
    else if (SFI_SUBMIT_PIN == dwFieldID)
    {
        *pdwAdjacentTo = SFI_SUBMIT_PIN; // standalone Sign-in button
        hr = S_OK;
    }
    else
    {
        hr = E_INVALIDARG;
    }
    return hr;
}

// Sets the value of a field which can accept a string as a value.
// This is called on each keystroke when a user types into an edit field
HRESULT PassRecCredential::SetStringValue(DWORD dwFieldID, _In_ PCWSTR pwz)
{
    HRESULT hr = E_INVALIDARG;

    if (dwFieldID < ARRAYSIZE(_rgFieldStatePairs) &&
        (CPFT_EDIT_TEXT == _rgCredProvFieldDescriptors[dwFieldID].cpft ||
            CPFT_PASSWORD_TEXT == _rgCredProvFieldDescriptors[dwFieldID].cpft))
    {
        PWSTR* ppwszStored = &_rgFieldStrings[dwFieldID];

        //replace previously stored value
        CoTaskMemFree(*ppwszStored); 
        hr = SHStrDupW(pwz, ppwszStored);
    }

    return hr;
}

// Returns the checked state and label for a checkbox field
HRESULT PassRecCredential::GetCheckboxValue(DWORD dwFieldId, _Out_ BOOL *pbChecked, _Outptr_result_nullonfailure_ PWSTR *ppwszLabel)
{
    if (!pbChecked || !ppwszLabel)
    {
        return E_INVALIDARG;
    }
    *ppwszLabel = nullptr;
    HRESULT hr = E_INVALIDARG;

    if (dwFieldId < ARRAYSIZE(_rgCredProvFieldDescriptors) && _rgCredProvFieldDescriptors[dwFieldId].cpft == CPFT_CHECKBOX)
    {
        *pbChecked = _fPinChecked;
        hr = SHStrDupW(_rgFieldStrings[dwFieldId], ppwszLabel);
    }
    return hr; 
}

HRESULT PassRecCredential::SetCheckboxValue(DWORD dwFieldId, BOOL bChecked) 
{
    HRESULT hr = E_INVALIDARG;
    LPWSTR rawUsername = wcsrchr(_pszQualifiedUserName, L'\\') ? wcsrchr(_pszQualifiedUserName, L'\\') + 1 : _pszQualifiedUserName;
    
    // If unexpiration is disabled prevent further toggling
    if (_fUnexpirationDisabled)
    {
        LOG(L"[SetCheckboxValue] Skipping SetCheckboxValue because unexpiration was disabled earlier.");
        return S_FALSE;
    }

    if (!_pCredProvCredentialEvents) return E_POINTER;

    if (dwFieldId < ARRAYSIZE(_rgCredProvFieldDescriptors) && _rgCredProvFieldDescriptors[dwFieldId].cpft == CPFT_CHECKBOX)
    {
        if (dwFieldId == SFI_PIN_CHECKBOX)
        {
            LOG(L"[SetCheckboxValue] PIN option toggled");
            _fPinChecked = bChecked;

            if (bChecked) { // PIN flow selected: hide Bitlocker checkbox and show sign-in button
                _fPinChecked = TRUE;
                _fBitlockerChecked = FALSE;
                _pCredProvCredentialEvents->BeginFieldUpdates();
                _pCredProvCredentialEvents->SetFieldState(this, SFI_BITLOCKER_CHECKBOX, CPFS_HIDDEN);
                _pCredProvCredentialEvents->SetFieldState(this, SFI_SUBMIT_PIN, CPFS_DISPLAY_IN_SELECTED_TILE);
                _pCredProvCredentialEvents->SetFieldString(this, SFI_SUBMIT_PIN, L"Confirm");
                _pCredProvCredentialEvents->EndFieldUpdates();
                LOG(L"[SetCheckboxValue] User checked 'I remember my PIN'. Setting password expired flag.\n");
                WritetoRegistry(L"credential-provider-expire", rawUsername, STATUS_USER_CHECKED_BOX, RESULT_SUCCESS, false);

                
            }
            else {
                // Prevent unchecking if password reset is in progress
                if (IsTempPasswordStillSet(_pszQualifiedUserName))
                {
                    LOG(L"[PasswordCheck] TryTempPasswordLogin called");

                    _fUnexpirationDisabled = true;

                    if (_pCredProvCredentialEvents)
                    {
                        _pCredProvCredentialEvents->BeginFieldUpdates();

                        _pCredProvCredentialEvents->SetFieldCheckbox(this, SFI_PIN_CHECKBOX, TRUE, L"");
                        _pCredProvCredentialEvents->SetFieldState(this, SFI_PIN_CHECKBOX, CPFS_DISPLAY_IN_SELECTED_TILE);
                        _pCredProvCredentialEvents->SetFieldInteractiveState(this, SFI_PIN_CHECKBOX, CPFIS_DISABLED);
                        _pCredProvCredentialEvents->SetFieldState(this, SFI_SUBMIT_PIN, CPFS_HIDDEN);
                        _pCredProvCredentialEvents->SetFieldState(this, SFI_PIN_HINT_TEXT, CPFS_DISPLAY_IN_SELECTED_TILE);
                        _pCredProvCredentialEvents->SetFieldString(this, SFI_PIN_HINT_TEXT, L"Uncheck disabled as Password Reset is in progress");
                        _pCredProvCredentialEvents->EndFieldUpdates();
                    }
                
                    LOG(L"[SetCheckboxValue] Uncheck disabled as Password Reset is in progress (verified via login test).");
                    WritetoRegistry(L"credential-provider-expire", rawUsername, STATUS_PASSWORD_UNEXPIRATION_DISABLED, RESULT_UNEXPIRATION_DISABLED, false);
                    return S_FALSE;
                }

                // Re-enable Bitlocker options and revert password expiration
                _pCredProvCredentialEvents->BeginFieldUpdates();
                _pCredProvCredentialEvents->SetFieldState(this, SFI_BITLOCKER_CHECKBOX, CPFS_DISPLAY_IN_SELECTED_TILE);
                _pCredProvCredentialEvents->SetFieldState(this, SFI_SUBMIT_PIN, CPFS_HIDDEN);
                _pCredProvCredentialEvents->EndFieldUpdates();

                LOG(L"[SetCheckboxValue] PIN checkbox unchecked. Reverting password expiration flag using USER_INFO_3.\n");
                WritetoRegistry(L"credential-provider-expire", rawUsername, STATUS_USER_UNCHECKED_BOX, RESULT_SUCCESS, false);

                LPUSER_INFO_3 pUsr = nullptr;
                DWORD dwParmError = 0;

                NET_API_STATUS getStatus = NetUserGetInfo(NULL, rawUsername, 3, (LPBYTE*)&pUsr);
                if (getStatus == NERR_Success && pUsr)
                {
                    pUsr->usri3_password_expired = FALSE;

                    NET_API_STATUS setStatus = NetUserSetInfo(NULL, rawUsername, 3, (LPBYTE)pUsr, &dwParmError);
                    NetApiBufferFree(pUsr);

                    if (setStatus == NERR_Success)
                    {
                        WritetoRegistry(L"credential-provider-expire", rawUsername, STATUS_PASSWORD_UNEXPIRATION_SET, RESULT_SUCCESS, false);
                        LOG(L"[SetCheckboxValue] Successfully cleared password expiration flag using USER_INFO_3.");
                        hr = S_OK;

                        //UpdatePasswordInfo();
                    }
                    else
                    {
                        WritetoRegistry(L"credential-provider-expire", rawUsername, STATUS_PASSWORD_UNEXPIRATION_FAILED, RESULT_UNEXPIRATION_FAILED, false);
                        WCHAR buf[128];
                        swprintf_s(buf, L"[SetCheckboxValue] Failed to clear password expiration flag. Code: %lu\n", setStatus);
                        LOG(buf);
                        hr = HRESULT_FROM_WIN32(setStatus);
                    }
                }
                else
                {
                    WritetoRegistry(L"credential-provider-expire", rawUsername, STATUS_USER_INFO_FAILED, RESULT_USERINFO_FAILED, false);
                    WCHAR buf[128];
                    swprintf_s(buf, L"[SetCheckboxValue] NetUserGetInfo (level 3) failed. Code: %lu\n", getStatus);
                    LOG(buf);
                    hr = HRESULT_FROM_WIN32(getStatus);
                }

                // Optionally clear UI message
                if (_pCredProvCredentialEvents)
                {
                    _pCredProvCredentialEvents->BeginFieldUpdates();
                    _pCredProvCredentialEvents->SetFieldString(this, SFI_PIN_HINT_TEXT, L"");
                    _pCredProvCredentialEvents->SetFieldState(this, SFI_PIN_HINT_TEXT, CPFS_HIDDEN);
                    _pCredProvCredentialEvents->EndFieldUpdates();
                }
            }
        }
        else if (dwFieldId == SFI_BITLOCKER_CHECKBOX)
        {
            LOG(L"[SetCheckboxValue] Bitlocker option toggled");
            _fBitlockerChecked = bChecked;
            if (bChecked) // Bitlocker flow selected: hide PIN checkbox and show Bitlocker input field
            {
                _fPinChecked = FALSE;
                _pCredProvCredentialEvents->BeginFieldUpdates();
                _pCredProvCredentialEvents->SetFieldState(this, SFI_PIN_CHECKBOX, CPFS_HIDDEN);

                _pCredProvCredentialEvents->SetFieldState(this, SFI_BITLOCKER_KEY, CPFS_DISPLAY_IN_SELECTED_TILE);
                _pCredProvCredentialEvents->SetFieldState(this, SFI_SUBMIT_BUTTON, CPFS_DISPLAY_IN_SELECTED_TILE);
                _pCredProvCredentialEvents->SetFieldState(this, SFI_HELPWINDOW_LINK, CPFS_DISPLAY_IN_SELECTED_TILE);
                _pCredProvCredentialEvents->EndFieldUpdates();
            }
            else
            {
                // Re-enable PIN checkbox options
                _pCredProvCredentialEvents->BeginFieldUpdates();
                _pCredProvCredentialEvents->SetFieldState(this, SFI_PIN_CHECKBOX, CPFS_DISPLAY_IN_SELECTED_TILE);

                _pCredProvCredentialEvents->SetFieldState(this, SFI_BITLOCKER_KEY, CPFS_HIDDEN);
                _pCredProvCredentialEvents->SetFieldState(this, SFI_SUBMIT_BUTTON, CPFS_HIDDEN);
                _pCredProvCredentialEvents->SetFieldState(this, SFI_HELPWINDOW_LINK, CPFS_HIDDEN);
                _pCredProvCredentialEvents->EndFieldUpdates();
            }
        }
    }
    
    return hr; 
}

// Combo box is intentionally not implemented for this CP - returning 0 items prevents LogonUI from attempting to render it
HRESULT PassRecCredential::GetComboBoxValueCount(DWORD dwFieldID, _Out_ DWORD* pcItems, _Deref_out_range_(< , *pcItems) _Out_ DWORD* pdwSelectedItem)
{
    UNREFERENCED_PARAMETER(dwFieldID);

    if (!pcItems || !pdwSelectedItem)
    {
        return E_INVALIDARG;
    }

    *pcItems = 0;
    *pdwSelectedItem = 0;

    return E_NOTIMPL;
}
HRESULT PassRecCredential::GetComboBoxValueAt(DWORD dwFieldID, DWORD dwItem, _Outptr_result_nullonfailure_ PWSTR* ppwszItem)
{
    HRESULT hr;
    *ppwszItem = nullptr;

    // Validate parameters. Defensive implementation in case a combobox field is introduced later
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) &&
        (CPFT_COMBOBOX == _rgCredProvFieldDescriptors[dwFieldID].cpft))
        {
        hr = SHStrDupW(s_rgComboBoxStrings[dwItem], ppwszItem);
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}
//combo box selection changes not supported
HRESULT PassRecCredential::SetComboBoxSelectedValue(DWORD, DWORD) { return E_NOTIMPL; }

//handles clicks on command-link style fields
HRESULT PassRecCredential::CommandLinkClicked(DWORD dwFieldID)
{
    LOG(L"[Credential] Command Link Clicked");
    HRESULT hr = S_OK;

    // Validate parameter.
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) &&
        (CPFT_COMMAND_LINK == _rgCredProvFieldDescriptors[dwFieldID].cpft))
    {
        HWND hwndOwner = nullptr;
        switch (dwFieldID)
        {
        case SFI_HELPWINDOW_LINK:
        {
            // retrieve logon ui window handle
            if (_pCredProvCredentialEvents)
            {
                _pCredProvCredentialEvents->OnCreatingWindow(&hwndOwner);
            }

            // MessageBoxTimeoutW impelementation to avoid indefinite blocking
            HMODULE hUser32 = GetModuleHandle(L"user32.dll");
            if (hUser32)
            {
                auto pMessageBoxTimeoutW = reinterpret_cast<MessageBoxTimeoutW_t>(GetProcAddress(hUser32, "MessageBoxTimeoutW"));

                if (pMessageBoxTimeoutW)
                {
                    pMessageBoxTimeoutW(
                        hwndOwner,
                        L"To find your BitLocker recovery key:\n - Personal account: aka.ms/myrecoverykey\n - Work or school account: aka.ms/aadrecoverykey\n - Saved or printed recovery key file\n\n Use another device if needed, then enter the key here.",
                        L"Where to Find BitLocker Recovery Key",
                        0,
                        0,
                        45 * 1000
                    );
                }
                else
                {
                    // fallback to older method
                    ::MessageBox(hwndOwner, L"To find your BitLocker recovery key:\n - Personal account: aka.ms/myrecoverykey\n - Work or school account: aka.ms/aadrecoverykey\n - Saved or printed recovery key file\n\n Use another device if needed, then enter the key here.", L"Where to Find BitLocker Recovery Key", 0);
                }
            }

            break;
        }
        default:
            hr = E_INVALIDARG;
        }

    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// retrieves password status for a local user using USER_INFO_3
PasswordInfo GetPasswordInfo(LPCWSTR userName)
{
    PasswordInfo info = {};
    LPUSER_INFO_3 pUserInfo = nullptr;

    NET_API_STATUS status = NetUserGetInfo(nullptr, userName, 3, (LPBYTE*)&pUserInfo);
    if (status != NERR_Success || !pUserInfo)
    {
        LOG(L"[GetPasswordInfo] NetUserGetInfo failed or returned null for user: " + std::wstring(userName ? userName : L"<null>"));
        return info;
    }
    if (pUserInfo->usri3_password_expired)
        info.isExpired = true;
    if (pUserInfo->usri3_flags & UF_PASSWORD_EXPIRED)
        info.mustChangePassword = true;
    if (pUserInfo->usri3_flags & UF_LOCKOUT)
        info.isLocked = true;

    DWORD ageSeconds = pUserInfo->usri3_password_age;
    info.passwordAgeDays = ageSeconds / (60 * 60 * 24); // convert password age from seconds to days

    WCHAR buf[256];
    swprintf_s(buf, 256,
        L"[GetPasswordInfo] user=%s | expired=%d mustChange=%d locked=%d age=%lu days",
        userName ? userName : L"<null>",
        info.isExpired,
        info.mustChangePassword,
        info.isLocked,
        info.passwordAgeDays);
    LOG(buf);

    NetApiBufferFree(pUserInfo);
    return info;
}

// updates password status info in the credential UI, currently not in use
void PassRecCredential::UpdatePasswordInfo()
{
    if (!_pCredProvCredentialEvents || !_pszQualifiedUserName)
        return;

    LPWSTR rawUsername = wcsrchr(_pszQualifiedUserName, L'\\') ? wcsrchr(_pszQualifiedUserName, L'\\') + 1 : _pszQualifiedUserName;
    PasswordInfo pInfo = GetPasswordInfo(rawUsername);

    WCHAR infoText[512];
    swprintf_s(infoText, 512,
        L"Password Info:\n Expired: %s\n Must Change: %s\n Locked: %s\n Age: %lu day(s)",
        pInfo.isExpired ? L"Yes" : L"No",
        pInfo.mustChangePassword ? L"Yes" : L"No",
        pInfo.isLocked ? L"Yes" : L"No",
        pInfo.passwordAgeDays);

    _pCredProvCredentialEvents->BeginFieldUpdates();
    // _pCredProvCredentialEvents->SetFieldState(this, SFI_PASSWORD_INFO_TEXT, CPFS_DISPLAY_IN_SELECTED_TILE);
    // _pCredProvCredentialEvents->SetFieldString(this, SFI_PASSWORD_INFO_TEXT, infoText);
    _pCredProvCredentialEvents->EndFieldUpdates();
}


// Performs validation (BitLocker Recovery Key) and recovery actions (password reset/expire) and returns status to LogonUI
HRESULT PassRecCredential::GetSerialization(
    _Out_ CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE *pcpgsr,
    _Out_ CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION *pcpcs,
    _Outptr_result_maybenull_ PWSTR *ppwszOptionalStatusText,
    _Out_ CREDENTIAL_PROVIDER_STATUS_ICON *pcpsiOptionalStatusIcon)
{
    LOG(L"[GetSerialization] GetSerialization called\n");
    *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
    *ppwszOptionalStatusText = nullptr;
    *pcpsiOptionalStatusIcon = CPSI_NONE;
    ZeroMemory(pcpcs, sizeof(*pcpcs));
    HRESULT hr = E_UNEXPECTED;

    // Extra check to block recovery options on domain joined devices (already gets blocked via SetSelected)
    if (IsMachineDomainJoined())
    {
        LOG(L"[DomainCheck] Blocking GetSerialization because device is domain joined.");
        SHStrDupW(L"Password Recovery options are disabled because this device is joined to a domain.", ppwszOptionalStatusText);
        *pcpsiOptionalStatusIcon = CPSI_WARNING;
        *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;

        return S_OK;
    }

    // Convert DOMAIN\User to SAM compatible username
    PWSTR rawUsername = wcsrchr(_pszQualifiedUserName, L'\\') ? wcsrchr(_pszQualifiedUserName, L'\\') + 1 : _pszQualifiedUserName;

    // Prevent any flow if account is currently locked
    if (rawUsername && *rawUsername)
    {
        PasswordInfo info = GetPasswordInfo(rawUsername);
        if (info.isLocked)
        {
            LOG(L"[GetSerialization] User account is locked. Blocking login attempt.");
            SHStrDupW(L"Account is locked. Please wait 5 minutes and try again.", ppwszOptionalStatusText);
            *pcpsiOptionalStatusIcon = CPSI_ERROR;
            *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
            return S_OK;   // important : avoid credential submission
        }
    }

    //------------------ PIN based recovery flow -------------------------------------
    if (_fPinChecked)
    {
        LOG(L"[GetSerialization] PIN-based flow selected");
        LPUSER_INFO_3 pUsrFlags = nullptr;
        NET_API_STATUS flagGetStatus = NetUserGetInfo(NULL, rawUsername, 3, (LPBYTE*)&pUsrFlags);
        
        if (flagGetStatus == NERR_Success && pUsrFlags != nullptr)
        {
            if (pUsrFlags->usri3_flags & UF_DONT_EXPIRE_PASSWD)
            {
                pUsrFlags->usri3_flags &= ~UF_DONT_EXPIRE_PASSWD;
                NET_API_STATUS flagSetStatus = NetUserSetInfo(NULL, rawUsername, 3, (LPBYTE)pUsrFlags, nullptr);
                WCHAR flagBuf[128];
                swprintf_s(flagBuf, L"[GetSerialization] NetUserSetInfo returned: %lu\n", flagSetStatus);
                LOG(flagBuf);
                LOG(L"[GetSerialization] Password Never Expires flag was set. Cleared automatically.\n");
            }
            NetApiBufferFree(pUsrFlags);
        }

        LPUSER_INFO_3 pUsr = nullptr;
        DWORD dwParmError = 0;
        NET_API_STATUS getStatus = NetUserGetInfo(NULL, rawUsername, 3, (LPBYTE*)&pUsr);
        WCHAR buf[128];
        swprintf_s(buf, L"[GetSerialization] NetUserGetInfo returned: %lu\n", getStatus);
        LOG(buf);

        if (getStatus == NERR_Success && pUsr != nullptr)
        {
            // Force password change at next logon by expiring password
            pUsr->usri3_password_expired = TRUE;
            NET_API_STATUS setStatus = NetUserSetInfo(NULL, rawUsername, 3, (LPBYTE)pUsr, &dwParmError);
            NetApiBufferFree(pUsr);
            swprintf_s(buf, L"[GetSerialization] NetUserSetInfo returned: %lu\n", setStatus);
            LOG(buf);
            if (setStatus == NERR_Success)
            {
                WritetoRegistry(L"credential-provider-expire", rawUsername, STATUS_PASSWORD_EXPIRATION_SET, RESULT_SUCCESS, true);
                LOG(L"[GetSerialization] Password expired successfully.\n");
                SHStrDupW(L"Please log in with your PIN and change your password when prompted.", ppwszOptionalStatusText);
                *pcpsiOptionalStatusIcon = CPSI_SUCCESS;
                *pcpgsr = CPGSR_NO_CREDENTIAL_FINISHED;

                // Hide submit button to prevent repeated execution
                if (_pCredProvCredentialEvents)
                {
                    _pCredProvCredentialEvents->BeginFieldUpdates();
                    _pCredProvCredentialEvents->SetFieldState(this, SFI_SUBMIT_PIN, CPFS_HIDDEN);
                    _pCredProvCredentialEvents->EndFieldUpdates();
                }

                return S_OK;
            }
            else
            {
                LOG(L"[GetSerialization] Failed to set password expired flag.\n");
                WritetoRegistry(L"credential-provider-expire", rawUsername, STATUS_PASSWORD_EXPIRATION_FAILED, RESULT_EXPIRATION_FAILED, true);
                SHStrDupW(L"Failed to expire password.", ppwszOptionalStatusText);
                *pcpsiOptionalStatusIcon = CPSI_ERROR;
                *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
                return HRESULT_FROM_WIN32(setStatus);
            }
        }
        else 
        {
            WritetoRegistry(L"credential-provider-expire", rawUsername, STATUS_USER_INFO_FAILED, RESULT_USERINFO_FAILED, true);
            LOG(L"[GetSerialization] Failed to retrieve user info.\n");
            SHStrDupW(L"Failed to retrieve user info.", ppwszOptionalStatusText);
            *pcpsiOptionalStatusIcon = CPSI_ERROR;
            *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
            return HRESULT_FROM_WIN32(getStatus);
        }
    }

    //------------------------- BitLocker based recovery flow ---------------------------------
    if (_rgFieldStrings[SFI_BITLOCKER_KEY])
    {
        LOG(L"[GetSerialization] BitLocker-based flow selected");
        LOG(L"[GetSerialization] In BitLocker Verification block\n");

            std::wstring expectedKey = GetBitlockerRecoveryKey();

            if (!expectedKey.empty())
            {
                std::wstring inputKey(_rgFieldStrings[SFI_BITLOCKER_KEY]);

                // normalise key for comparison (removing dashes from input)
                inputKey.erase(std::remove(inputKey.begin(), inputKey.end(), L'-'), inputKey.end());
                expectedKey.erase(std::remove(expectedKey.begin(), expectedKey.end(), L'-'), expectedKey.end());

                LOG((L"[BitLocker] Entered: " + inputKey + L"\n").c_str());
                LOG((L"[BitLocker] Expected: " + expectedKey + L"\n").c_str());

                if (inputKey == expectedKey)
                {
                    LOG(L"[GetSerialization] BitLocker key verified. Setting new password...\n");

                    // clearing Password never expires flag if set
                    LPUSER_INFO_3 pUsrFlags = nullptr;
                    NET_API_STATUS flagStatus = NetUserGetInfo(NULL, rawUsername, 3, (LPBYTE*)&pUsrFlags);

                    if (flagStatus == NERR_Success && pUsrFlags != nullptr)
                    {
                        if (pUsrFlags->usri3_flags & UF_DONT_EXPIRE_PASSWD)
                        {
                            pUsrFlags->usri3_flags &= ~UF_DONT_EXPIRE_PASSWD;
                            NET_API_STATUS flagSetStatus = NetUserSetInfo(NULL, rawUsername, 3, (LPBYTE)pUsrFlags, nullptr);
                            WCHAR flagBuf[128];
                            swprintf_s(flagBuf, L"[GetSerialization] NetUserSetInfo returned: %lu\n", flagSetStatus);
                            LOG(flagBuf);
                            LOG(L"[GetSerialization] Password Never Expires flag was set. Cleared automatically.\n");
                        }
                        NetApiBufferFree(pUsrFlags);
                    }

                    // setting temporary known password
                    USER_INFO_1003 ui1003 = {};
                    ui1003.usri1003_password = const_cast<LPWSTR>(L"TempP@ss123");

                    NET_API_STATUS status = NetUserSetInfo(NULL, rawUsername, 1003, (LPBYTE)&ui1003, nullptr);

                    if(status!=NERR_Success)
                    {
                        WritetoRegistry(L"credential-provider-reset", rawUsername, STATUS_PASSWORD_RESET_FAILED, RESULT_RESET_FAILED, true);
                        WCHAR buf[128];
                        swprintf_s(buf, L"[GetSerialization] Failed to set password. Code: %lu\n", status);
                        LOG(buf);
                        *ppwszOptionalStatusText = _wcsdup(L"Failed to reset password.");
                        *pcpsiOptionalStatusIcon = CPSI_ERROR;
                        return S_FALSE;
                    }
                    
                    LOG(L"[GetSerialization] Password set to TempP@ss123\n");

                    // force password reset at next logon by expiring new password
                    LPUSER_INFO_3 pUsr = nullptr;
                    DWORD dwParmError = 0;
                    NET_API_STATUS getStatus = NetUserGetInfo(NULL, rawUsername, 3, (LPBYTE*)&pUsr);
                    WCHAR buf[128];
                    swprintf_s(buf, L"[GetSerialization] NetUserGetInfo returned: %lu\n", getStatus);
                    LOG(buf);
                    if (getStatus == NERR_Success && pUsr != nullptr)
                    {
                        pUsr->usri3_password_expired = TRUE;
                            
                        NET_API_STATUS status2 = NetUserSetInfo(NULL, rawUsername, 3, (LPBYTE)pUsr, &dwParmError);
                        NetApiBufferFree(pUsr);
                        swprintf_s(buf, L"[GetSerialization] NetUserSetInfo returned: %lu\n", status2);
                        LOG(buf);
                        if (status2 == NERR_Success)
                        {
                            LOG(L"[GetSerialization] Password expiration flag set\n");
                            WritetoRegistry(L"credential-provider-reset", rawUsername, STATUS_PASSWORD_RESET_SUCCESS, RESULT_SUCCESS, true);

                            // Clear BitLocker key field
                            CoTaskMemFree(_rgFieldStrings[SFI_BITLOCKER_KEY]);
                            SHStrDupW(L"", &_rgFieldStrings[SFI_BITLOCKER_KEY]);

                            // If UI events available, update field
                            if (_pCredProvCredentialEvents)
                            {
                                _pCredProvCredentialEvents->SetFieldString(this, SFI_BITLOCKER_KEY, _rgFieldStrings[SFI_BITLOCKER_KEY]);
                            }

                            //UpdatePasswordInfo();
                            SHStrDupW(L"Password reset to 'TempP@ss123'. Please change it at next logon.", ppwszOptionalStatusText);
                            *pcpsiOptionalStatusIcon = CPSI_SUCCESS;
                            *pcpgsr = CPGSR_NO_CREDENTIAL_FINISHED;
                            return S_OK;
                        }
                        else
                        {
                            WritetoRegistry(L"credential-provider-reset", rawUsername, STATUS_PASSWORD_EXPIRATION_FAILED, RESULT_EXPIRATION_FAILED, true);
                            swprintf_s(buf, L"[GetSerialization] Failed to set password expiration flag. Code: %lu\n", status2);
                            LOG(buf);
                            *ppwszOptionalStatusText = _wcsdup(L"Could not enforce password change on next logon.");
                            *pcpsiOptionalStatusIcon = CPSI_WARNING;
                            return S_FALSE;
                        }
                    }
                    else {
                        WritetoRegistry(L"credential-provider-reset", rawUsername, STATUS_USER_INFO_FAILED, RESULT_USERINFO_FAILED, true);
                        swprintf_s(buf, L"[GetSerialization] NetUserGetInfo failed. Code: %lu\n", getStatus);
                        LOG(buf);
                        *ppwszOptionalStatusText = _wcsdup(L"Could not read user flags to set expiration.");
                        *pcpsiOptionalStatusIcon = CPSI_WARNING;
                        return S_FALSE;                      
                    }
                } 
                else
                {
                    WritetoRegistry(L"credential-provider-reset", rawUsername, STATUS_BITLOCKER_KEY_FAILED, RESULT_KEY_MISMATCH, true);
                    LOG(L"[BitLocker] BitLocker key mismatch\n");
                    SHStrDupW(L"Incorrect BitLocker Recovery Key.", ppwszOptionalStatusText);
                    *pcpsiOptionalStatusIcon = CPSI_ERROR;
                    return S_FALSE;
                }
            }
            else {
                WritetoRegistry(L"credential-provider-reset", rawUsername, STATUS_KEY_NOT_FOUND, RESULT_KEY_NOT_FOUND, true);
                LOG(L"[GetSerialization] Failed to retrieve BitLocker Key\n");
                *ppwszOptionalStatusText = _wcsdup(L"Could not retrieve recovery key.");
                *pcpsiOptionalStatusIcon = CPSI_WARNING;
                return S_FALSE;
            }
    }

    //Pasword Reset using new password from user
    //if (_rgFieldStrings[SFI_NEW_PASSWORD] && _rgFieldStrings[SFI_CONFIRM_PASSWORD])
    //{
    //    LogToFile(L"In password reset block\n");
    //    LogToFile((L"New: " + std::wstring(_rgFieldStrings[SFI_NEW_PASSWORD]) + L"\n").c_str());
    //    LogToFile((L"Confirm: " + std::wstring(_rgFieldStrings[SFI_CONFIRM_PASSWORD]) + L"\n").c_str());
    //    LogToFile((L"Target user: " + std::wstring(_pszQualifiedUserName ? _pszQualifiedUserName : L"<null>") + L"\n").c_str());

    //    PWSTR rawUsername = wcsrchr(_pszQualifiedUserName, L'\\') ? wcsrchr(_pszQualifiedUserName, L'\\') + 1 : _pszQualifiedUserName;
    //    LogToFile(L"Passing to NetUserSetInfo: " + std::wstring(rawUsername));

    //    if (wcscmp(_rgFieldStrings[SFI_NEW_PASSWORD], _rgFieldStrings[SFI_CONFIRM_PASSWORD]) == 0)
    //    {
    //        USER_INFO_1003 ui;
    //        ui.usri1003_password = const_cast<LPWSTR>(_rgFieldStrings[SFI_NEW_PASSWORD]);
    //        //DWORD dwParamErr = 0;

    //        NET_API_STATUS nStatus = NetUserSetInfo(
    //            NULL,
    //            rawUsername,
    //            1003,
    //            (LPBYTE)&ui,
    //            nullptr
    //        );
    //        WCHAR msg[256];
    //        swprintf_s(msg, 256, L"NetUserSetInfo returned status: %lu", nStatus);
    //        LogToFile(msg);

    //        if (nStatus == NERR_Success)
    //        {
    //            LogToFile(L"Password Updated successfully\n");
    //            *pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;
    //            return S_OK;
    //        }
    //        else
    //        {
    //            WCHAR buf[128];
    //            swprintf_s(buf, L"NetUserSetInfo failed. Code: %lu\n", nStatus);
    //            LogToFile(buf);

    //            *ppwszOptionalStatusText = _wcsdup(L"Failed to set password.");
    //            *pcpsiOptionalStatusIcon = CPSI_ERROR;
    //            return HRESULT_FROM_WIN32(nStatus);
    //        }
    //    }
    //    else
    //    {
    //        LogToFile(L"Passwords do not match\n");
    //        *ppwszOptionalStatusText = _wcsdup(L"Passwords do not match.");
    //        *pcpsiOptionalStatusIcon = CPSI_WARNING;
    //        return S_FALSE;
    //    }
    //}
    hr = E_FAIL;
    LOG(L"[GetSerialization] Exiting GetSerialization with code: " + std::to_wstring(hr));
    return hr;
}

// maps logon NTSTATUS pairs to user friendly messages and icons
struct REPORT_RESULT_STATUS_INFO
{
    NTSTATUS ntsStatus;
    NTSTATUS ntsSubstatus;
    PWSTR     pwzMessage;
    CREDENTIAL_PROVIDER_STATUS_ICON cpsi;
};

// known logon failure senarios we want to customize
static const REPORT_RESULT_STATUS_INFO s_rgLogonStatusInfo[] =
{
    { STATUS_LOGON_FAILURE, STATUS_SUCCESS, L"Incorrect password or username.", CPSI_ERROR, },
    { STATUS_ACCOUNT_RESTRICTION, STATUS_ACCOUNT_DISABLED, L"The account is disabled.", CPSI_WARNING },
    { STATUS_ACCOUNT_RESTRICTION, STATUS_ACCOUNT_LOCKED_OUT, L"The account is locked.", CPSI_ERROR },
};

// ReportResult is completely optional.  Its purpose is to allow a credential to customize the string
// and the icon displayed in the case of a logon failure. 
HRESULT PassRecCredential::ReportResult(NTSTATUS ntsStatus,
                                        NTSTATUS ntsSubstatus,
                                        _Outptr_result_maybenull_ PWSTR *ppwszOptionalStatusText,
                                        _Out_ CREDENTIAL_PROVIDER_STATUS_ICON *pcpsiOptionalStatusIcon)
{
    *ppwszOptionalStatusText = nullptr;
    *pcpsiOptionalStatusIcon = CPSI_NONE;

    DWORD dwStatusInfo = (DWORD)-1;

    // Look for a match on status and substatus.
    for (DWORD i = 0; i < ARRAYSIZE(s_rgLogonStatusInfo); i++)
    {
        if (s_rgLogonStatusInfo[i].ntsStatus == ntsStatus && s_rgLogonStatusInfo[i].ntsSubstatus == ntsSubstatus)
        {
            dwStatusInfo = i;
            break;
        }
    }

    if ((DWORD)-1 != dwStatusInfo)
    {
        if (SUCCEEDED(SHStrDupW(s_rgLogonStatusInfo[dwStatusInfo].pwzMessage, ppwszOptionalStatusText)))
        {
            *pcpsiOptionalStatusIcon = s_rgLogonStatusInfo[dwStatusInfo].cpsi;
        }
    }
    // Since nullptr is a valid value for *ppwszOptionalStatusText and *pcpsiOptionalStatusIcon
    // this function can't fail.
    return S_OK;
}

// Gets the SID of the user corresponding to the credential.
HRESULT PassRecCredential::GetUserSid(_Outptr_result_nullonfailure_ PWSTR *ppszSid)
{
    *ppszSid = nullptr;
    HRESULT hr = E_UNEXPECTED;
    if (_pszUserSid != nullptr)
    {
        hr = SHStrDupW(_pszUserSid, ppszSid);
    }
    // Return S_FALSE with a null SID in ppszSid for the
    // credential to be associated with an empty user tile.

    return hr;
}

// GetFieldOptions to enable the password reveal button and touch keyboard auto-invoke in the password field.
HRESULT PassRecCredential::GetFieldOptions(DWORD dwFieldID,
                                           _Out_ CREDENTIAL_PROVIDER_CREDENTIAL_FIELD_OPTIONS *pcpcfo)
{
    *pcpcfo = CPCFO_NONE;

    if (dwFieldID == SFI_TILEIMAGE)
    {
        *pcpcfo = CPCFO_ENABLE_TOUCH_KEYBOARD_AUTO_INVOKE;
    }

    return S_OK;
}
