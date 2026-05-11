
# Windows Password Recovery Provider

A custom Windows Credential Provider that enables password recovery directly from the Windows logon screen.

The provider supports:
- BitLocker Recovery Key–based password reset
- Windows Hello PIN–based password expiration

Both flows enforce password change at next login for improved security.

---

## Demo

### BitLocker Recovery Flow

https://github.com/user-attachments/assets/f9a26386-5b87-497b-8d60-165b2ce719d2

### PIN Recovery Flow

https://github.com/user-attachments/assets/3e938f3b-6cd5-478d-a437-077c5b0157c3

---

## Features

- BitLocker recovery key validation
- Windows Hello PIN recovery flow
- Secure password reset using `NetUserSetInfo`
- Forced password change at next sign-in
- Dynamic Credential Provider UI
- Registry/debug logging support
- Installer-based deployment

---

## Requirements

- Windows 10/11
- Local administrator privileges
- BitLocker enabled (for BitLocker recovery flow)
- Local user account support only

---

## Download

Download the latest installer from the [Releases](../../releases) page.

---

## Installation

1. Run:

   ```bash
   windows-password-recovery.exe
   ```

2. Restart the machine after installation.

3. The Password Recovery tile should appear on the Windows login screen.

---

## Recovery Flows

### 🔹 BitLocker Recovery Flow

1. Select the Password Recovery tile
2. Enter the BitLocker recovery key
3. Password is reset to a temporary value
4. User is forced to change password at next login

This flow validates the BitLocker recovery key and then uses standard Win32 APIs to reset and expire the password. The final password change is handled through the built-in Windows password change process.

### 🔹 PIN Recovery Flow

1. Select the PIN recovery option
2. Password expiration flag is set
3. User logs in using Windows Hello PIN
4. Windows prompts for a new password

This flow does not directly reset the password. It expires the existing password and relies on the standard Windows password change process after successful Windows Hello authentication.

> **Note:**  
> The BitLocker recovery flow performs a password reset and may invalidate existing app sessions or credentials tied to the previous password.  
> The PIN recovery flow is less disruptive and preserves the existing password until changed by the user.

---

## Security Notes

- No plaintext password storage
- Password reset requires BitLocker recovery key validation or existing Windows Hello PIN access
- Recovery flows rely on existing Windows authentication and recovery mechanisms
- Password reset and expiration operations use standard Win32 APIs (`NetUserSetInfo`)
- Temporary passwords are expired immediately
-  Optional logging support avoids storing sensitive information

---

## Limitations

- Supports local accounts only
- Domain and Azure AD accounts are not currently supported

---

## References

This project is based on Microsoft's Credential Provider sample framework:

- [https://github.com/microsoft/windows-classic-samples/tree/main/Samples/CredentialProvider](https://github.com/Microsoft/Windows-classic-samples/tree/main/Samples/CredentialProvider)

The implementation extends the sample architecture with custom recovery workflows and UI behavior.
