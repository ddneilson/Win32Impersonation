# Checking whether the SID obtained from TokenUser is different from TokenOwner, and
# how that compares to the SID of the user & current process.

import win32security
import win32process

curr_proc = win32process.GetCurrentProcess()
ph = win32security.OpenProcessToken(curr_proc, win32security.TOKEN_ALL_ACCESS)
tok_info = win32security.GetTokenInformation(ph, win32security.TokenUser)

lh = win32security.LogonUser("jobuser", None, "arandom12@!", win32security.LOGON32_LOGON_INTERACTIVE, win32security.LOGON32_PROVIDER_DEFAULT)
lh_user_info = win32security.GetTokenInformation(lh, win32security.TokenUser)
lh_owner_sid = win32security.GetTokenInformation(lh, win32security.TokenOwner)

acc = win32security.LookupAccountName(None, "jobuser")

print("CurrentProcess SID: ", str(tok_info[0]))
print("JobUser Account SID:", str(acc[0]))
print("JobUser Logon token SID:", str(lh_user_info[0]))
print("JobUser Logon owner SID:", str(lh_owner_sid))

# CurrentProcess SID:      PySID:S-1-5-21-1165846310-3337698221-3261425632-500
# JobUser Account SID:     PySID:S-1-5-21-1165846310-3337698221-3261425632-1003
# JobUser Logon token SID: PySID:S-1-5-21-1165846310-3337698221-3261425632-1003
# JobUser Logon owner SID: PySID:S-1-5-21-1165846310-3337698221-3261425632-1003
