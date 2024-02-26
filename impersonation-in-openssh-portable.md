# Understanding Impersonation in OpenSSH-Portable

This is a series of notes on the openssh-portable implementation; goal being to understand which win32 APIs they are using, and why. Reason: `sshd` already does the sort of impersonation that I’m interested in understanding.

Source code: https://github.com/PowerShell/openssh-portable

Note: When connecting to a Windows host with ssh, two new sshd processes will get created: 1 owned by SYSTEM (the user sshd is running as), and another owned by the logon user. You also get 2 additional logon user processes — conhost.exe & cmd.exe.


1. openssh: [ssh_login](https://github.com/PowerShell/openssh-portable/blob/5622b51825b997bc5a958923f837bd1442fa05d0/sshconnect.c#L1598)
    1. “Starts a dialog with the server, and authenticates the current user on the server”
    2. This is called at the end of ssh.c:main(). This is the function that the client system is using to connect to the server. Seemingly NOT important.
2. openssh: sshd.c:[main](https://github.com/PowerShell/openssh-portable/blob/5622b51825b997bc5a958923f837bd1442fa05d0/sshd.c#L1981) (note: [wmain wrapper](https://github.com/PowerShell/openssh-portable/blob/5622b51825b997bc5a958923f837bd1442fa05d0/contrib/win32/win32compat/wmain_sshd.c#L225) that ultimately ends up in the posix main)
    1. Post-authentication block starts [here](https://github.com/PowerShell/openssh-portable/blob/5622b51825b997bc5a958923f837bd1442fa05d0/sshd.c#L2782)
        1. Two candidates: [privsep_postauth](https://github.com/PowerShell/openssh-portable/blob/5622b51825b997bc5a958923f837bd1442fa05d0/sshd.c#L875) or [do_authenticated](https://github.com/PowerShell/openssh-portable/blob/5622b51825b997bc5a958923f837bd1442fa05d0/session.c#L336)
            1. privset_postauth is only called if `use_privsep` — it’s kind of looking like “privilege separation” is the codeword for “we’re running a subprocess here”
                1. privset_postauth has a call to __posix_spawn_asuser that looks promising. 
                2. Will continue here
            2. do_authenticated ends up in [server_loop2](https://github.com/PowerShell/openssh-portable/blob/5622b51825b997bc5a958923f837bd1442fa05d0/serverloop.c#L340)
                1. server_loop2 looks like it’s the packet-forwarding code path. I’m not seeing anything in here that looks like spawning subprocesses; on the contrary, there’s what looks clearly like reading and then writing input packets to an output connection.
                2. Dead end.
3. openssh: [privsep_postauth](https://github.com/PowerShell/openssh-portable/blob/5622b51825b997bc5a958923f837bd1442fa05d0/sshd.c#L875)
    1. Note: FORK_NOT_SUPPORTED appears to be defined in the windows build: [win32/openssh/config.h.vs](https://github.com/PowerShell/openssh-portable/blob/5622b51825b997bc5a958923f837bd1442fa05d0/contrib/win32/openssh/config.h.vs#L1729)
    2. This code branches based on whether the global [privsep_auth_child](https://github.com/PowerShell/openssh-portable/blob/5622b51825b997bc5a958923f837bd1442fa05d0/sshd.c#L212) is true or not
        1. privsep_auth_child is 0 for the main daemon/server process, and 1 for the child process.
    3. [privsep_child_cmdline](https://github.com/PowerShell/openssh-portable/blob/5622b51825b997bc5a958923f837bd1442fa05d0/sshd.c#L699) constructs the command that is going to be run.
        1. If we’re the main sshd daemon/service, then:
            1. First time, this is exactly [the `argv` for the process plus the addition of the -R option](https://github.com/PowerShell/openssh-portable/blob/5622b51825b997bc5a958923f837bd1442fa05d0/sshd.c#L2489-L2499).
                1. [-R handling](https://github.com/PowerShell/openssh-portable/blob/5622b51825b997bc5a958923f837bd1442fa05d0/sshd.c#L2079-L2082) sets the rexeced_flag=1, which in turn results in the rexec_flag being set to 0
            2. Second time, this is exactly the[argv for the top-level sshd plus the addition of the  `-z` or `-y` option](https://github.com/PowerShell/openssh-portable/blob/5622b51825b997bc5a958923f837bd1442fa05d0/sshd.c#L707-L726).
                1. [-z/-y handling in main](https://github.com/PowerShell/openssh-portable/blob/5622b51825b997bc5a958923f837bd1442fa05d0/sshd.c#L2148-L2159) — sets privsep_auth_child to 1 (which affects the behavior or privsep_postauth), and file-scoped static rexec_flag = 0 (which affects the behavior of main(); rexec_flag is 1 by default in the main sshd daemon/service process)
            3. tl;dr: SYSTEM:`sshd`  → SYSTEM:`sshd -R` → user:`sshd -z`
                1. The user:`sshd -z` is acting as a pseudoterminal (see: [PTY Implementation details](https://github.com/PowerShell/Win32-OpenSSH/wiki/TTY-PTY-support-in-Windows-OpenSSH#pty))
    4. [__posix_spawn_asuser](https://github.com/PowerShell/openssh-portable/blob/5622b51825b997bc5a958923f837bd1442fa05d0/contrib/win32/win32compat/spawn-ext.c#L9) handles running the child process dictated by privsep_child_cmdline
4. openssh: [__posix_spawn_asuser](https://github.com/PowerShell/openssh-portable/blob/5622b51825b997bc5a958923f837bd1442fa05d0/contrib/win32/win32compat/spawn-ext.c#L9)
    1. First gets an auth token:
        1. password_auth_token global var, if it’s set.
            1. set exclusively in [windows_password_auth](https://github.com/PowerShell/openssh-portable/blob/5622b51825b997bc5a958923f837bd1442fa05d0/contrib/win32/win32compat/win32_usertoken_utils.c#L778C1-L778C22)... called from only [auth_password](https://github.com/PowerShell/openssh-portable/blob/5622b51825b997bc5a958923f837bd1442fa05d0/auth-passwd.c#L78C1-L78C14)... called via [mm_answer_authpassword](https://github.com/PowerShell/openssh-portable/blob/5622b51825b997bc5a958923f837bd1442fa05d0/monitor.c#L912C1-L912C23).. called via [monitor_child_postauth](https://github.com/PowerShell/openssh-portable/blob/5622b51825b997bc5a958923f837bd1442fa05d0/monitor.c#L392C1-L392C23).. called via main ([here](https://github.com/PowerShell/openssh-portable/blob/5622b51825b997bc5a958923f837bd1442fa05d0/sshd.c#L923)).
                1. Note: monitor_child_postauth is running through auth methods that are added to a dispatch table. [mm_answer_authpassword](https://github.com/PowerShell/openssh-portable/blob/5622b51825b997bc5a958923f837bd1442fa05d0/monitor.c#L912C1-L912C23) is added to that table.
                2. The callsite in main() to monitor_child_postauth is in the `sshd -R` process’ code path *AFTER* it has already called __posix_spawn_asuser; so, I believe that password_auth_token will be unset in the `sshd -R` process' path to create the `sshd -z` process as the logon user.
            2. openssh: [windows_password_auth](https://github.com/PowerShell/openssh-portable/blob/5622b51825b997bc5a958923f837bd1442fa05d0/contrib/win32/win32compat/win32_usertoken_utils.c#L778C1-L778C22)
                1. First tries win32:[LogonUserExExW](https://learn.microsoft.com/en-us/windows/win32/secauthn/logonuserexexw) with LOGON32_LOGON_NETWORK_CLEARTEXT & LOGON_PROVIDER_DEFAULT
                    1. “This function is similar to the[LogonUserEx](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-logonuserexw)function, except that it takes the additional parameter, *pTokenGroups” ...* openssh is passing NULL for pTokenGroup. openssh is also passing NULL for the args that LogonUserExW adds to [LogonUserW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-logonuserw); so, they seemingly could have used LogonUserW here with no change in behavior.
                2. If that fails and the error isn’t ERROR_PASSWORD_MUST_CHANGE then it tries for a “custom LSA authentication”
                    1. Going to skip this for now; we’ll accept a limitation that our code doesn’t handle [“custom LSA” configurations.](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)
        2. else sspi_auth_user global var, if it’s set.
            1. [set](https://github.com/PowerShell/openssh-portable/blob/5622b51825b997bc5a958923f837bd1442fa05d0/contrib/win32/win32compat/gss-sspi.c#L944) exlusively in [gss_accept_sec_context](https://github.com/PowerShell/openssh-portable/blob/5622b51825b997bc5a958923f837bd1442fa05d0/contrib/win32/win32compat/gss-sspi.c#L809) ... called via [ssh_gssapi_accept_ctx](https://github.com/PowerShell/openssh-portable/blob/5622b51825b997bc5a958923f837bd1442fa05d0/gss-serv.c#L185C1-L185C22)... 
                1. called via [mm_answer_gss_accept_ctx](https://github.com/PowerShell/openssh-portable/blob/5622b51825b997bc5a958923f837bd1442fa05d0/monitor.c#L2002C1-L2002C25)
                2. or called via [input_gssapi_token](https://github.com/PowerShell/openssh-portable/blob/5622b51825b997bc5a958923f837bd1442fa05d0/auth2-gss.c#L145C1-L145C19)
                3. or others.
            2. Intialized by calling win32:[QuerySecurityContextToken](https://learn.microsoft.com/en-us/windows/win32/api/sspi/nf-sspi-querysecuritycontexttoken) which is an element of a “Security Context Dispatch Table” populated by win32:[InitSecurityInterfaceW](https://learn.microsoft.com/en-us/windows/win32/api/sspi/nf-sspi-initsecurityinterfacew)
                1. Related to clients configured for [SSPI](https://learn.microsoft.com/en-us/windows/win32/rpc/security-support-provider-interface-sspi-)
                2. **Going to skip this for now**; we’ll accept a limitation that our code doesn’t handle this sort of system configuration yet.
        3. else [get_user_token](https://github.com/PowerShell/openssh-portable/blob/latestw_all/contrib/win32/win32compat/win32_usertoken_utils.c#L317)
            1. It looks to me like we end up here to fetch the token for the as-user `sshd -z` process.
    2. Then [load_user_profile](https://github.com/PowerShell/openssh-portable/blob/5622b51825b997bc5a958923f837bd1442fa05d0/contrib/win32/win32compat/win32_usertoken_utils.c#L399), but *ONLY* if the target user is ‘sshd’
        1. I suspect that this is intended to be a development/debug flow; I’ve seen other cases where they check for ‘sshd’ user and do special development-only things.
    3. Then calls [posix_spawn_internal](https://github.com/PowerShell/openssh-portable/blob/5622b51825b997bc5a958923f837bd1442fa05d0/contrib/win32/win32compat/w32fd.c#L1245) with that token.
5. openssh: [get_user_token](https://github.com/PowerShell/openssh-portable/blob/5622b51825b997bc5a958923f837bd1442fa05d0/contrib/win32/win32compat/win32_usertoken_utils.c#L317C1-L317C15)
    1. Three code paths:
        1. (irrelevant for us) a development/debug flow that checks if running as the ‘sshd’ user.[Interesting docstring here](https://github.com/PowerShell/openssh-portable/blob/5622b51825b997bc5a958923f837bd1442fa05d0/contrib/win32/win32compat/win32_usertoken_utils.c#L541), though — they just clone the current process token, but have commented-out code for resetting the sshd user’s password and then doing a LogonUserW. 
        2. If NOT running a the SYSTEM user ([code to check](https://github.com/PowerShell/openssh-portable/blob/5622b51825b997bc5a958923f837bd1442fa05d0/contrib/win32/win32compat/misc.c#L1587)), then they use the current process’ token — duplicating it if not impersonating; we’re always impersonating from the __posix_spawn_asuser() flow, though.
            1. Uses: `[OpenProcessToken](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocesstoken)([GetCurrentProcess](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getcurrentprocess)(), TOKEN_ALL_ACCESS_P, &t1)` 
                1. TOKEN_ALL_ACCESS_P [seems to be](https://github.com/search?q=TOKEN_ALL_ACCESS_P+language%3AC&type=code&l=C) the following [access rights](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-rights-for-access-token-objects): 
                    1. STANDARD_RIGHTS_REQUIRED (i.e. DELETE|READ_CONTROL|WRITE_DAC|WRITE_OWNER) ([eg](https://github.com/ziglang/zig/blob/256c5934bfc19d3b8a1cf01bc07c9ad86a6c6524/lib/std/os/windows.zig#L3095))
                    2. TOKEN_ASSIGN_PRIMARY
                    3. TOKEN_DUPLICATE
                    4. TOKEN_IMPERSONATE
                    5. TOKEN_QUERY
                    6. TOKEN_QUERY_SOURCE
                    7. TOKEN_ADJUST_PRIVILEGES
                    8. TOKEN_ADJUST_GROUPS
                    9. TOKEN_ADJUST_DEFAULT
            2. Unused: [`DuplicateToken`](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-duplicatetoken)`(t1, `[`SecurityIdentification`](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-security_impersonation_level)`, &token)` in the “not impersonation” codepath
        3. If running as the SYSTEM user, only the [line 375 code path](https://github.com/PowerShell/openssh-portable/blob/5622b51825b997bc5a958923f837bd1442fa05d0/contrib/win32/win32compat/win32_usertoken_utils.c#L375) is relevant since `impersonation` is 1. So, call [generate_s4u_user_token](https://github.com/PowerShell/openssh-portable/blob/5622b51825b997bc5a958923f837bd1442fa05d0/contrib/win32/win32compat/win32_usertoken_utils.c#L98) with impersonation=1
6. openssh: [generate_s4u_user_token](https://github.com/PowerShell/openssh-portable/blob/5622b51825b997bc5a958923f837bd1442fa05d0/contrib/win32/win32compat/win32_usertoken_utils.c#L98) with impersonation=1
    1. `domain_user = wcschr(user_cpn, L'\\') != NULL;` (i.e. if there’s a NetBiosDomain in the username)
    2. `[InitLsaString](https://learn.microsoft.com/en-us/windows/win32/secmgmt/using-lsa-unicode-strings)(&logon_process_name, __progname);` then
    3. `[LsaRegisterLogonProcess](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-lsaregisterlogonprocess)(&logon_process_name, &lsa_handle, &mode) != STATUS_SUCCESS)` (log error if not successful); then
        1. This “establishes a connection to the LSA server and verifies that the caller is a logon application.”
            1. **TODO**: What makes an application a “logon application” ??
    4. `InitLsaString(&auth_package_name, (domain_user) ? MICROSOFT_KERBEROS_NAME_A : MSV1_0_PACKAGE_NAME);` then
    5. [`LsaLookupAuthenticationPackage`](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-lsalookupauthenticationpackage)`(lsa_handle, &auth_package_name, &auth_package_id)` then
        1. “obtains the unique identifier of an authentication package”
    6. <whole bunch of string manipulation to construct the “s4u_logon” name as dictated by being a domain user or not>.
    7. Intialize a [TOKEN_SOURCE](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_source) structure: `strcpy_s(source_context.SourceName, TOKEN_SOURCE_LENGTH, "sshd") != 0 || [AllocateLocallyUniqueId](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-allocatelocallyuniqueid)(&source_context.SourceIdentifier) != TRUE)` then
    8. `InitLsaString(&origin_name, "sshd");`
    9. `[LsaLogonUser](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-lsalogonuser)(lsa_handle, &origin_name, Network, auth_package_id, logon_info, (ULONG)logon_info_size, NULL, &source_context ...`
7. <recapping> __posix_spawn_asuser has obtained a logon token via LsaLogonUser, indirectly from get_user_token. Next it calls posix_spawn_internal with the resulting logon token. (yes, the functions being called “posix_*” for windows codepaths is extremely confusing)
8. openssh: [posix_spawn_internal](https://github.com/PowerShell/openssh-portable/blob/5622b51825b997bc5a958923f837bd1442fa05d0/contrib/win32/win32compat/w32fd.c#L1245)
    1. Clones a pile of file handles (stdout, etc), and then calls [spawn_child_internal](https://github.com/PowerShell/openssh-portable/blob/5622b51825b997bc5a958923f837bd1442fa05d0/contrib/win32/win32compat/w32fd.c#L1050) 
9. openssh: [spawn_child_internal](https://github.com/PowerShell/openssh-portable/blob/5622b51825b997bc5a958923f837bd1442fa05d0/contrib/win32/win32compat/w32fd.c#L1050)
    1. Interesting... this can spawn multiple child processes. The ‘cmd’ can be multiple null-terminated strings appended to one another; it’ll run each null-terminated string as a separate process.
    2. For the impersonation case
        1. `b = [CreateProcessAsUserW](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasusera)(as_user, NULL, t, NULL, NULL, TRUE, flags, NULL, NULL, &si, &pi);`
    3. For the non-impersonation case (i.e. not running ‘as_user’):
        1. `b = [CreateProcessW](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw)(NULL, t, NULL, NULL, TRUE, flags, NULL, NULL, &si, &pi);`
10. That’s it. At this point, we have an `sshd -z` running as `user`. This sshd process will then run `cmd.exe`.
Finally, how is “cmd.exe” started??

1. In the [server_loop2](https://github.com/PowerShell/openssh-portable/blob/5622b51825b997bc5a958923f837bd1442fa05d0/serverloop.c#L340) code path  of [do_authenticated](https://github.com/PowerShell/openssh-portable/blob/5622b51825b997bc5a958923f837bd1442fa05d0/session.c#L336) as called from main:
    1. The loop is “dispatching” inputs, and one of those inputs is a pty-style: [here](https://github.com/PowerShell/openssh-portable/blob/5622b51825b997bc5a958923f837bd1442fa05d0/serverloop.c#L896)
    2. That call to [session_input_channel_req](https://github.com/PowerShell/openssh-portable/blob/5622b51825b997bc5a958923f837bd1442fa05d0/session.c#L2231) is called with a “pty-req” or “shell” request-type, I believe. Either way, you end up in [do_exec](https://github.com/PowerShell/openssh-portable/blob/5622b51825b997bc5a958923f837bd1442fa05d0/session.c#L663) which [calls](https://github.com/PowerShell/openssh-portable/blob/5622b51825b997bc5a958923f837bd1442fa05d0/session.c#L724-L727) to [do_exec_pty](https://github.com/PowerShell/openssh-portable/blob/latestw_all/contrib/win32/win32compat/w32-doexec.c#L576)
    3. That ends up calling [do_exec_windows](https://github.com/PowerShell/openssh-portable/blob/5622b51825b997bc5a958923f837bd1442fa05d0/contrib/win32/win32compat/w32-doexec.c#L312) which, in turn calls [exec_command_with_pty](https://github.com/PowerShell/openssh-portable/blob/5622b51825b997bc5a958923f837bd1442fa05d0/contrib/win32/win32compat/win32_pty.c#L68)
    4. That [constructs](https://github.com/PowerShell/openssh-portable/blob/5622b51825b997bc5a958923f837bd1442fa05d0/contrib/win32/win32compat/win32_pty.c#L93) the command: `wchar_t *cmd_fmt = L"%ls\\conhost.exe --headless --width %d --height %d --signal 0x%x -- %ls";`  
        1. e.g. `C:\Windows\system32\conhost.exe —headless —width 120 —height 30 —signal 0x23c — "c:\windows\system32\cmd.exe"` on my test box
            1. Note: To see command-line args, run this in a cmd shell: `WMIC path win32_process get Caption,Processid,Commandline`
    5. And ultimately [calls](https://github.com/PowerShell/openssh-portable/blob/5622b51825b997bc5a958923f837bd1442fa05d0/contrib/win32/win32compat/win32_pty.c#L127) to [CreateProcessW](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw) to run the command.

