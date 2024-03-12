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

### Testing Matrix

Testing setup:
* Account running the application: Host
* Account the subprocess runs under: Target
* Using impersonation flow: LogonTokenW -> LoadUserProfileW -> CreateProcessAsUserW
* Running "C:\Windows\System32\whoami.exe" as the impersonated user.
* Logout then relogin after every account permissions change.

Account properties/privileges shorthand:

| Shorthand | Meaning |
| --------- | ------------------ |
| A         | Account is marked as an Administrator |
| U         | Account is a non-admin user account |
| PT        | Account has SE_ASSIGNPRIMARYTOKEN_NAME privilege |
| B         | Account has "Log on as batch job" privilege |
| S         | Account has "Log on as service" privilege |
| LS        | LOGON32_LOGON_SERVICE passed to LogonUserW |
| LB        | LOGON32_LOGON_BATCH passed to LogonUserW |
| LI        | LOGON32_LOGON_INTERACTIVE passed to LogonUserW |

Tests:

|                                | Host running a service | LocalSystem running a service | Host running interactively | Host running interactively via ssh |
| ------------------------------ | ---------------------- | ----------------------------- | -------------------------- | ---------------------------------- |
| LS / Host: A,S / Target: U     | 1385: Logon failure-User has not been granted the requested logon type | 1385: Logon failure-User has not been granted the requested logon type  | 1385: Logon failure-User has not been granted the requested logon type | 1385: Logon failure-User has not been granted the requested logon type |
| LB / Host: A,S / Target: U     | 1385: Logon failure-User has not been granted the requested logon type | 1385: Logon failure-User has not been granted the requested logon type | 1385: Logon failure-User has not been granted the requested logon type | 1385: Logon failure-User has not been granted the requested logon type |
| LI / Host: A,S / Target: U     | 1314: A required privilege not held by the client | :white_check_mark: Sucess | 1314: A required privilege not held by the client | 1314: A required privilege not held by the client |
| LS / Host: A,S / Target: U,B,S | 1314: A required privilege not held by the client | :white_check_mark: Sucess | 1314: A required privilege not held by the client | 1314: A required privilege not held by the client |
| LB / Host: A,S / Target: U,B,S | 1314: A required privilege not held by the client | :white_check_mark: Sucess | 1314: A required privilege not held by the client | 1314: A required privilege not held by the client |
| LI / Host: A,S / Target: U,B,S | 1314: A required privilege not held by the client | :white_check_mark: Sucess | 1314: A required privilege not held by the client | 1314: A required privilege not held by the client |
| LS / Host: A,S,PT / Target: U,B,S | :white_check_mark: Sucess | :white_check_mark: Sucess | whoami.exe: Application unable to start correctly (0xc0000142) | :white_check_mark: Sucess |
| LB / Host: A,S,PT / Target: U,B,S | :white_check_mark: Sucess | :white_check_mark: Sucess | whoami.exe: Application unable to start correctly (0xc0000142) | :white_check_mark: Sucess |
| LI / Host: A,S,PT / Target: U,B,S | :white_check_mark: Sucess | :white_check_mark: Sucess | whoami.exe: Application unable to start correctly (0xc0000142) | :white_check_mark: Sucess |
| LS / Host: A,S,PT / Target: A,B,S | :white_check_mark: Sucess | :white_check_mark: Sucess | :white_check_mark: Sucess | :white_check_mark: Sucess |
| LB / Host: A,S,PT / Target: A,B,S | :white_check_mark: Sucess | :white_check_mark: Sucess | :white_check_mark: Sucess | :white_check_mark: Sucess |
| LI / Host: A,S,PT / Target: A,B,S | :white_check_mark: Sucess | :white_check_mark: Sucess | whoami.exe: Application unable to start correctly (0xc0000142) | :white_check_mark: Sucess |

* "Running interactively" = `ProductionCandidate> python local_test.py`
* "Running a service" = `ProductionCandidate> install & run service_test.py`

## Using CreateProcessWithLogonW

* [CreateProcessWithLogonW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithlogonw)

Using thie API requires that the caller *NOT* be running in Session 0.

## Using CreateProcessWithTokenW

Focusing on using:
* [LogonUserW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-logonuserw); then
* [CreateProcessWithTokenW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)

The documentation says that "The process that calls CreateProcessWithTokenW must have the SE_IMPERSONATE_NAME privilege."
(aka: "Impersonate a client after authentication"; aka: "SeImpersonatePrivilege")

Notes:
* When just using CreateProcessWithTokenW, targetting a non-admin user while running the parent process as Administrator I was
  reliably experiencing a error 0xC0000142 in the subprocess. I found a workaround that entails adding the Security ID (SID) of
  the target user to both the parent process' Window Station & Desktop's Access Control List (ACL). This not not seem correct/proper
  to me -- it's a perminant mutation of the system ACLs, and broadly allows the target user this access rather than just the subprocess
  that we're creating. I wouldn't use this hack in production, but it's sufficient for trying to sort out some of the permissions boundaries
  of CreateProcessWithTokenW.

### Testing Matrix

Testing setup:
* Account running the application: Host
* Account the subprocess runs under: Target
* Using impersonation flow: LogonTokenW ->  CreateProcessWithTokenW
    * LOGON32_LOGON_INTERACTIVE passed to LogonUserW
    * LOGON_WITH_PROFILE passed to CreateProcessWithTokenW
    * CREATE_NEW_PROCESS_GROUP | CREATE_UNICODE_ENVIRONMENT passed as creationflags to CreateProcessWithTokenW
* Running "C:\Windows\System32\whoami.exe" as the impersonated user.
* Logout then relogin after every account permissions change.


| Shorthand | Meaning |
| --------- | ------------------ |
| A         | Account is marked as an Administrator |
| U         | Account is a non-admin user account |
| PT        | Account has SE_ASSIGNPRIMARYTOKEN_NAME privilege |
| PA        | Account has SE_IMPERSONATE_NAME privilege |
| PD        | Account has SE_DELEGATE_SESSION_USER_IMPERSONATE_NAME privilege |

Tests:

|                                | Host running a service    | LocalSystem running a service |  Host running interactively | Host running interactively via ssh |
| ------------------------------ | ------------------------- | ----------------------------- |  -------------------------- | ---------------------------------- |
| Host: A, PA; Target: U         | :white_check_mark: Sucess | :white_check_mark: Sucess     | :white_check_mark: Sucess   | :white_check_mark: Sucess          |
| Host: U; Target: U             | Note1 | N/A | Note2 - SetUserObjectSecurity: Error 1307 - This security ID may not be assigned as the owner of this object | CreateEnvironmentBlock: Error 5 - Access denied. |
| Host: U,PT; Target: U          | Note1 | N/A | Note2 - SetUserObjectSecurity: Error 1307 - This security ID may not be assigned as the owner of this object | CreateEnvironmentBlock: Error 5 - Access denied. |
| Host: U,PA; Target: U          | Note1 | N/A | Note2 - SetUserObjectSecurity: Error 1307 - This security ID may not be assigned as the owner of this object | CreateEnvironmentBlock: Error 5 - Access denied. |
| Host: U,PA,PT; Target: U       | Note1 | N/A | Note2 - SetUserObjectSecurity: Error 1307 - This security ID may not be assigned as the owner of this object | CreateEnvironmentBlock: Error 5 - Access denied. |
| Host: U,PA,PT,PD; Target: U    | Note1 | N/A | Note2 - SetUserObjectSecurity: Error 1307 - This security ID may not be assigned as the owner of this object | CreateEnvironmentBlock: Error 5 - Access denied. |

* Note1 - Getting an error likely related to the Python install w.r.t. the service. Error: "Incorrect function"
* Note2 - SetUserObjectSecurity is part of the hack to set the ACL of the Window Station & Desktop ACL. This 
  error is encountered when trying to set the ACL for the Window Station (which is what we try to set first)
