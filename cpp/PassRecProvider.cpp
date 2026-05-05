
#include <initguid.h>
#include "PassRecProvider.h"
#include "PassRecCredential.h"
#include "guid.h"

PassRecProvider::PassRecProvider():
    _cRef(1),
    _pCredProviderUserArray(nullptr)
{
    DllAddRef();
}

PassRecProvider::~PassRecProvider()
{
    _ReleaseEnumeratedCredentials();

    if (_pCredProviderUserArray != nullptr)
    {
        _pCredProviderUserArray->Release();
        _pCredProviderUserArray = nullptr;
    }

    DllRelease();
}

bool PassRecProvider::IsLocalAccount(PCWSTR userName)
{
    if (!userName)
        return false;
    
    std::wstring name(userName);

    if (name.find(L"MicrosoftAccount\\") == 0 ||
        name.find(L"@") != std::wstring::npos)
    {
        return false;
    }

    size_t backslashPos = name.find(L'\\');
    if (backslashPos != std::wstring::npos)
    {
        std::wstring prefix = name.substr(0, backslashPos);

        WCHAR machineName[MAX_COMPUTERNAME_LENGTH + 1];
        DWORD len = MAX_COMPUTERNAME_LENGTH + 1;
        if (GetComputerNameW(machineName, &len))
        {
            if (_wcsicmp(prefix.c_str(), machineName) != 0)
                return false; 
        }
    }

    SID_NAME_USE sidType;
    DWORD sidSize = 0, domainSize = 0;

    LookupAccountNameW(nullptr, userName, nullptr, &sidSize, nullptr, &domainSize, &sidType);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
        return false;

    std::vector<BYTE> sid(sidSize);
    std::wstring domain(domainSize, L'\0');

    if (!LookupAccountNameW(nullptr, userName, sid.data(), &sidSize, &domain[0], &domainSize, &sidType))
    {
        return false;
    }

    WCHAR machineName[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD len = MAX_COMPUTERNAME_LENGTH + 1; 
    if (!GetComputerNameW(machineName, &len))
        return false;
    
    std::wstring domainStr(domain.data(), domainSize);
    domainStr.resize(wcslen(domain.data()));
    return (sidType == SidTypeUser && _wcsicmp(domainStr.c_str(), machineName) == 0);
}

// SetUsageScenario is the provider's cue that it's going to be asked for tiles
// in a subsequent call.
HRESULT PassRecProvider::SetUsageScenario(
    CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
    DWORD /*dwFlags*/)
{
    LOG(L"[Provider] SetUsageScenario called");
    HRESULT hr;

    // Decide which scenarios to support here. Returning E_NOTIMPL simply tells the caller
    // that we're not designed for that scenario.
    switch (cpus)
    {
    case CPUS_LOGON:
    case CPUS_UNLOCK_WORKSTATION:
        // The reason why we need _fRecreateEnumeratedCredentials is because ICredentialProviderSetUserArray::SetUserArray() is called after ICredentialProvider::SetUsageScenario(),
        // while we need the ICredentialProviderUserArray during enumeration in ICredentialProvider::GetCredentialCount()
        _cpus = cpus;
        _fRecreateEnumeratedCredentials = true;
        hr = S_OK;
        break;

    case CPUS_CHANGE_PASSWORD:
    case CPUS_CREDUI:
        hr = E_NOTIMPL;
        break;

    default:
        hr = E_INVALIDARG;
        break;
    }
    return hr;
}

// SetSerialization takes the kind of buffer that you would normally return to LogonUI for
// an authentication attempt.  It's the opposite of ICredentialProviderCredential::GetSerialization.
// GetSerialization is implement by a credential and serializes that credential.  Instead,
// SetSerialization takes the serialization and uses it to create a tile.
//
// SetSerialization is called for two main scenarios.  The first scenario is in the credui case
// where it is prepopulating a tile with credentials that the user chose to store in the OS.
// The second situation is in a remote logon case where the remote client may wish to
// prepopulate a tile with a username, or in some cases, completely populate the tile and
// use it to logon without showing any UI.
//
// If you wish to see an example of SetSerialization, please see either the SampleCredentialProvider
// sample or the SampleCredUICredentialProvider sample.  [The logonUI team says, "The original sample that
// this was built on top of didn't have SetSerialization.  And when we decided SetSerialization was
// important enough to have in the sample, it ended up being a non-trivial amount of work to integrate
// it into the main sample.  We felt it was more important to get these samples out to you quickly than to
// hold them in order to do the work to integrate the SetSerialization changes from SampleCredentialProvider
// into this sample.]
HRESULT PassRecProvider::SetSerialization(
    _In_ CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION const * /*pcpcs*/)
{
    return E_NOTIMPL;
}

// Called by LogonUI to give you a callback.  Providers often use the callback if they
// some event would cause them to need to change the set of tiles that they enumerated.
HRESULT PassRecProvider::Advise(
    _In_ ICredentialProviderEvents * /*pcpe*/,
    _In_ UINT_PTR /*upAdviseContext*/)
{
    LOG(L"[Provider] Advise called");
    return E_NOTIMPL;
}

// Called by LogonUI when the ICredentialProviderEvents callback is no longer valid.
HRESULT PassRecProvider::UnAdvise()
{
    LOG(L"[Provider] Unadvise called");
    return E_NOTIMPL;
}

// Called by LogonUI to determine the number of fields in your tiles.  This
// does mean that all your tiles must have the same number of fields.
// This number must include both visible and invisible fields. If you want a tile
// to have different fields from the other tiles you enumerate for a given usage
// scenario you must include them all in this count and then hide/show them as desired
// using the field descriptors.
HRESULT PassRecProvider::GetFieldDescriptorCount(
    _Out_ DWORD *pdwCount)
{
    *pdwCount = SFI_NUM_FIELDS;
    return S_OK;
}

// Gets the field descriptor for a particular field.
HRESULT PassRecProvider::GetFieldDescriptorAt(
    DWORD dwIndex,
    _Outptr_result_nullonfailure_ CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR **ppcpfd)
{
    HRESULT hr;
    *ppcpfd = nullptr;

    // Verify dwIndex is a valid field.
    if ((dwIndex < SFI_NUM_FIELDS) && ppcpfd)
    {
        hr = FieldDescriptorCoAllocCopy(s_rgCredProvFieldDescriptors[dwIndex], ppcpfd);
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Sets pdwCount to the number of tiles that we wish to show at this time.
// Sets pdwDefault to the index of the tile which should be used as the default.
// The default tile is the tile which will be shown in the zoomed view by default. If
// more than one provider specifies a default the last used cred prov gets to pick
// the default. If *pbAutoLogonWithDefault is TRUE, LogonUI will immediately call
// GetSerialization on the credential you've specified as the default and will submit
// that credential for authentication without showing any further UI.
HRESULT PassRecProvider::GetCredentialCount(
    _Out_ DWORD *pdwCount,
    _Out_ DWORD *pdwDefault,
    _Out_ BOOL *pbAutoLogonWithDefault)
{
    *pdwDefault = CREDENTIAL_PROVIDER_NO_DEFAULT;
    *pbAutoLogonWithDefault = FALSE;

    if (_fRecreateEnumeratedCredentials)
    {
        _fRecreateEnumeratedCredentials = false;
        _ReleaseEnumeratedCredentials();
        _CreateEnumeratedCredentials();
    }

    *pdwCount = static_cast<DWORD>(_pCredential.size());

    return S_OK;
}

// Returns the credential at the index specified by dwIndex. This function is called by logonUI to enumerate
// the tiles.
HRESULT PassRecProvider::GetCredentialAt(
    DWORD dwIndex,
    _Outptr_result_nullonfailure_ ICredentialProviderCredential **ppcpc)
{
    HRESULT hr = E_INVALIDARG;
    *ppcpc = nullptr;

    if ((dwIndex < _pCredential.size()) && ppcpc)
    {
        hr = _pCredential[dwIndex]->QueryInterface(IID_PPV_ARGS(ppcpc));
    }
    return hr;
}

// This function will be called by LogonUI after SetUsageScenario succeeds.
// Sets the User Array with the list of users to be enumerated on the logon screen.
HRESULT PassRecProvider::SetUserArray(_In_ ICredentialProviderUserArray *users)
{
    if (_pCredProviderUserArray)
    {
        _pCredProviderUserArray->Release();
    }
    _pCredProviderUserArray = users;
    _pCredProviderUserArray->AddRef();
    return S_OK;
}

void PassRecProvider::_CreateEnumeratedCredentials()
{
    switch (_cpus)
    {
    case CPUS_LOGON:
    case CPUS_UNLOCK_WORKSTATION:
        {
            _EnumerateCredentials();
            break;
        }
    default:
        break;
    }
}

void PassRecProvider::_ReleaseEnumeratedCredentials()
{
    for (auto* cred : _pCredential)
    {
        if (cred)
        {
            cred->Release();
        }
    }
    _pCredential.clear();
}

HRESULT PassRecProvider::_EnumerateCredentials()
{
    LOG(L"[Provider] Enumerating Credentials");
    HRESULT hr = E_UNEXPECTED;
    if (_pCredProviderUserArray != nullptr)
    {
        DWORD dwUserCount = 0;
        hr = _pCredProviderUserArray->GetCount(&dwUserCount);

        LOG(L"[Provider] User enumeration count=" + std::to_wstring(dwUserCount));
        if (SUCCEEDED(hr) && dwUserCount > 0)
        {
            for (DWORD i = 0; i < dwUserCount; i++)
            {
                ICredentialProviderUser* pCredUser = nullptr;
                if (SUCCEEDED(_pCredProviderUserArray->GetAt(i, &pCredUser)))
                {
                    PWSTR userName = nullptr;
                    if (SUCCEEDED(pCredUser->GetStringValue(PKEY_Identity_QualifiedUserName, &userName)) && userName)
                    {
                        LOG(L"[AccountCheck] Checking account type for user: " + std::wstring(userName));
                        if (!IsLocalAccount(userName))
                        {
                            LOG(L"[AccountCheck] Skipping non-local user: " + std::wstring(userName));
                            CoTaskMemFree(userName);
                            pCredUser->Release();
                            continue;
                        }
                        LOG(L"[AccountCheck] Including local user: " + std::wstring(userName));
                        CoTaskMemFree(userName);
                    }

                    auto* pCred = new(std::nothrow) PassRecCredential();
                    if (pCred != nullptr)
                    {
                        HRESULT hrInit = pCred->Initialize(_cpus, s_rgCredProvFieldDescriptors, s_rgFieldStatePairs, pCredUser);
                        if (SUCCEEDED(hrInit))
                        {
                            _pCredential.push_back(pCred);
                        }
                        else
                        {
                            pCred->Release();
                        }
                    }
                    else
                    {
                        hr = E_OUTOFMEMORY;
                    }
                    pCredUser->Release();
                }

            }
        }
        else
        {
            hr = E_FAIL;
        }
    }
    LOG(L"[Provider] Enumeration complete hr=" + std::to_wstring(hr));
    return hr;
}

// Boilerplate code to create our provider.
HRESULT PassRec_CreateInstance(_In_ REFIID riid, _Outptr_ void **ppv)
{
    HRESULT hr;
    PassRecProvider *pProvider = new(std::nothrow) PassRecProvider();
    if (pProvider)
    {
        hr = pProvider->QueryInterface(riid, ppv);
        pProvider->Release();
    }
    else
    {
        hr = E_OUTOFMEMORY;
    }
    return hr;
}
