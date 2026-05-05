#pragma once
#include "helpers.h"

// Logging Macro
#ifdef ENABLE_LOGGING
    void LogToFile(const std::wstring& message);
    #define LOG(msg) LogToFile(msg)
#else
    #define LOG(msg) ((void)0)
#endif

// Result codes written to registry
enum RESULT_CODE
{
    RESULT_SUCCESS = 0,
    RESULT_KEY_MISMATCH = 1,
    RESULT_RESET_FAILED = 2,
    RESULT_EXPIRATION_FAILED = 3,
    RESULT_USERINFO_FAILED = 4,
    RESULT_KEY_NOT_FOUND = 5,
    RESULT_UNEXPIRATION_FAILED = 6,
    RESULT_UNEXPIRATION_DISABLED = 7,
    RESULT_UNKNOWN_FAILURE = 99

};

// Status strings written to registry
#define STATUS_BITLOCKER_KEY_VERIFIED         L"BitLockerKeyVerified"
#define STATUS_BITLOCKER_KEY_FAILED           L"BitLockerKeyFailed"
#define STATUS_PASSWORD_RESET_SUCCESS         L"PasswordResetSuccess"
#define STATUS_PASSWORD_RESET_FAILED          L"PasswordResetFailed"
#define STATUS_PASSWORD_EXPIRATION_SET        L"PasswordExpirationSet"
#define STATUS_PASSWORD_EXPIRATION_FAILED     L"PasswordExpirationFailed"
#define STATUS_PASSWORD_UNEXPIRATION_SET      L"PasswordUnexpirationSet"
#define STATUS_PASSWORD_UNEXPIRATION_FAILED   L"PasswordUnexpirationFailed"
#define STATUS_PASSWORD_UNEXPIRATION_DISABLED L"PasswordUnexpirationDisabled"
#define STATUS_USER_INFO_FAILED               L"NetUserGetInfoFailed"
#define STATUS_USER_CHECKED_BOX               L"UserCheckedBox"
#define STATUS_USER_UNCHECKED_BOX             L"UserUncheckedBox"
#define STATUS_KEY_NOT_FOUND                  L"RecoveryKeyNotFound"
#define STATUS_UNKNOWN_ERROR                  L"UnexpectedError"

// Field IDs used by Credential UI. Order is important and must match field descripors and state arrays
enum FIELD_ID
{
    SFI_TILEIMAGE         = 0,
    SFI_LARGE_TEXT        = 1,
    SFI_PIN_CHECKBOX      = 2,
    SFI_SUBMIT_PIN        = 3,
    SFI_PIN_HINT_TEXT     = 4,
    SFI_BITLOCKER_CHECKBOX= 5,
    SFI_BITLOCKER_KEY     = 6,
    SFI_SUBMIT_BUTTON     = 7,
    SFI_HELPWINDOW_LINK   = 8,
   // SFI_PASSWORD_INFO_TEXT= 9,
    SFI_NUM_FIELDS        = 9,  // Note: if new fields are added, keep NUM_FIELDS last.  This is used as a count of the number of fields
};

// defines default visibility and interactivity of each field
struct FIELD_STATE_PAIR
{
    CREDENTIAL_PROVIDER_FIELD_STATE cpfs;
    CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE cpfis;
};

// initial field state configuration
static const FIELD_STATE_PAIR s_rgFieldStatePairs[] =
{
    { CPFS_DISPLAY_IN_SELECTED_TILE,   CPFIS_NONE    },    // SFI_TILEIMAGE
    { CPFS_DISPLAY_IN_SELECTED_TILE,   CPFIS_NONE    },    // SFI_LARGE_TEXT
    { CPFS_DISPLAY_IN_SELECTED_TILE,   CPFIS_NONE    },    // SFI_PIN_CHECKBOX
    { CPFS_HIDDEN,                     CPFIS_NONE    },    // SFI_SUBMIT_PIN
    { CPFS_HIDDEN,                     CPFIS_NONE    },    // SFI_PIN_HINT_TEXT
    { CPFS_DISPLAY_IN_SELECTED_TILE,   CPFIS_NONE    },    // SFI_BITLOCKER_CHECKBOX
    { CPFS_HIDDEN,                     CPFIS_NONE    },    // SFI_BITLOCKER_KEY
    { CPFS_HIDDEN,                     CPFIS_NONE    },    // SFI_SUBMIT_BUTTON
    { CPFS_HIDDEN,                     CPFIS_NONE    },    // SFI_HELPWINDOW_LINK
    //{ CPFS_DISPLAY_IN_SELECTED_TILE,   CPFIS_NONE    },    // SFI_PASSWORD_INFO_TEXT
};

//field descriptors defining UI type, labels and layout behaviour
static const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR s_rgCredProvFieldDescriptors[] =
{
    { SFI_TILEIMAGE,         CPFT_TILE_IMAGE,     L"Image",                                   CPFG_CREDENTIAL_PROVIDER_LOGO },
    { SFI_LARGE_TEXT,        CPFT_LARGE_TEXT,     L"Password Recovery Options"                                              },
    { SFI_PIN_CHECKBOX,      CPFT_CHECKBOX,       L"I remember my PIN. Sign in and change Password using Windows Hello PIN" },
    { SFI_SUBMIT_PIN,        CPFT_SUBMIT_BUTTON,  L"Confirm",                                 CPFG_STANDALONE_SUBMIT_BUTTON },           
    { SFI_PIN_HINT_TEXT,     CPFT_LARGE_TEXT,     L""                                                                       },
    { SFI_BITLOCKER_CHECKBOX,CPFT_CHECKBOX,       L"Reset Password using BitLocker Recovery Key"                            },
    { SFI_BITLOCKER_KEY,     CPFT_EDIT_TEXT,      L"BitLocker Recovery Key"                                                 },
    { SFI_SUBMIT_BUTTON,     CPFT_SUBMIT_BUTTON,  L"Submit"                                                                 },
    { SFI_HELPWINDOW_LINK,   CPFT_COMMAND_LINK,   L"Where to find my BitLocker key?"                                        },
   // { SFI_PASSWORD_INFO_TEXT,CPFT_SMALL_TEXT,     L""                                                                       },      
    
};

// placeholder combo box (not being used)
static const PWSTR s_rgComboBoxStrings[] =
{
    L"First",
    L"Second",
    L"Third",
};

// password state extracted from USER_INFO_3
struct PasswordInfo
{
    bool isExpired = false;
    bool mustChangePassword = false;
    bool isLocked = false;
    DWORD passwordAgeDays = 0;
};