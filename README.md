# Win32Impersonation

Some experimentation to try to figure out how to run processes as another user using Win32 APIs.

## Using CreateProcessAsUserW

Focusing on using:
* [LogonUserW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-logonuserw); then
* [LoadUserProfileW](https://learn.microsoft.com/en-us/windows/win32/api/userenv/nf-userenv-loaduserprofilew); then
* [CreateProcessAsUserW](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw)

To be able to use CreateProcessAsUserW, the documentation says:
"Typically, the process that calls the CreateProcessAsUser function must have the SE_INCREASE_QUOTA_NAME privilege and may require the SE_ASSIGNPRIMARYTOKEN_NAME privilege if the token is not assignable"

Furthermore, LoadUserProfileW documentation says:
"Starting with Windows XP Service Pack 2 (SP2) and Windows Server 2003, the caller must be an administrator or the LocalSystem account. It is not sufficient for the caller to merely impersonate the administrator or LocalSystem account."

This means that the calling user needs:
* To be:
    * LocalSystem; or
    * An Administrator with:
        * SE_ASSIGNPRIMARYTOKEN_NAME -- https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/replace-a-process-level-token
            * This may not be needed if LogonUserW is producing a token that is a restricted version of the caller's primary token.
        * SE_INCREASE_QUOTA_NAME -- https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/adjust-memory-quotas-for-a-process
            * Note: The Administrators group has this by default

Through experimentation, it additionally:
1. If the process is running in a Service context (i.e. Session ID = 0), then either it is running as:
    * LocalSystem; or
    * An Administrator user. (non-admin will be missing the required privileges)
        * Note: `ssh`ing into the host as an Administrative user is a way to force yourself to run within Session ID = 0.
2. If the process is running outside of a Service context (i.e. Session ID != 0), then:
    * The target user must also be an Administrator.
        * You will get a  "The application was unable to start correctly (0xc0000142)." error if the target is non-admin.
            * TODO - Figure out why this is the case. Something to do with the profile load? Another missing permission perhaps?

### LogonUserW

Requires:
* dwLogonType be either LOGON32_LOGON_BATCH or LOGON32_LOGON_SERVICE
    * LOGON32_LOGON_INTERACTIVE will lead to "The application was unable to start correctly (0xc0000142)." error starting the subprocess
      **if running outside of SessionID=0**. 
    * LOGON32_LOGON_INTERACTIVE *does* work if running within SessionID=0, though.

## Using CreateProcessWithLogonW

* [CreateProcessWithLogonW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithlogonw)

Using thie API requires that the caller *NOT* be running in Session 0.