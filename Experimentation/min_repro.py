import ctypes
from ctypes.wintypes import (
    BOOL,
    DWORD,
    HANDLE,
    LONG,
    LPCWSTR,
    LPWSTR,
    PDWORD,
    PHANDLE,
    ULONG,
)
from ctypes import (
    POINTER,
    WinError,
    WinDLL,
    byref
)
from collections.abc import Sequence
from contextlib import contextmanager
from typing import Generator

# https://learn.microsoft.com/en-us/windows/win32/api/profinfo/ns-profinfo-profileinfoa
class PROFILEINFO(ctypes.Structure):
    _fields_ = [
        ('dwSize', DWORD),
        ('dwFlags', DWORD),
        ('lpUserName', LPWSTR),
        ('lpProfilePath', LPWSTR),
        ('lpDefaultPath', LPWSTR),
        ('lpServerName', LPWSTR),
        ('lpPolicyPath', LPWSTR),
        ('hProfile', HANDLE)
    ]

# https://learn.microsoft.com/en-us/windows/win32/api/ntdef/ns-ntdef-luid
class LUID(ctypes.Structure):
    _fields_ = [
        ('LowPart', ULONG),
        ('HighPart', LONG)
    ]

class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ('Luid', LUID),
        ('Attributes', DWORD)
    ]

# https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_privileges
class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [
        ('PrivilegeCount', DWORD),
        # Note: To use
        #   ctypes.cast(ctypes.byref(self.Privileges), ctypes.POINTER(LUID_AND_ATTRIBUTES * self.PrivilegeCount)).contents
        ('Privileges', LUID_AND_ATTRIBUTES * 0)
    ]

    @staticmethod
    def allocate(length: int) -> 'TOKEN_PRIVILEGES':
        malloc_size_in_bytes = ctypes.sizeof(TOKEN_PRIVILEGES) + 2 * ctypes.sizeof(LUID_AND_ATTRIBUTES)
        malloc_buffer = (ctypes.c_byte * malloc_size_in_bytes)()
        token_privs = ctypes.cast(malloc_buffer, POINTER(TOKEN_PRIVILEGES))[0]
        token_privs.PrivilegeCount = length
        return token_privs
    
    def privileges_array(self) -> Sequence[LUID_AND_ATTRIBUTES]:
        return ctypes.cast(
            ctypes.byref(self.Privileges),
            ctypes.POINTER(LUID_AND_ATTRIBUTES * self.PrivilegeCount)
        ).contents

# ---------
# From: kernel32.dll
# ---------
kernel32 = WinDLL("kernel32")

# https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-closehandle
kernel32.CloseHandle.restype = BOOL
kernel32.CloseHandle.argtypes = [
    HANDLE # [in] hObject
]

# https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getcurrentprocess
kernel32.GetCurrentProcess.restype = HANDLE
kernel32.GetCurrentProcess.argtypes = []


CloseHandle = kernel32.CloseHandle
GetCurrentProcess = kernel32.GetCurrentProcess

# ---------
# From: advapi32.dll
# ---------
advapi32 = WinDLL("advapi32")

# https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-adjusttokenprivileges
advapi32.AdjustTokenPrivileges.restype = BOOL
advapi32.AdjustTokenPrivileges.argtypes = [
    HANDLE, # [in] TokenHandle
    BOOL, # [in] DisableAllPrivileges
    POINTER(TOKEN_PRIVILEGES), # [in, optional] NewState
    DWORD, # [in] BufferLength
    POINTER(TOKEN_PRIVILEGES), # [out, optional] PreviousState
    PDWORD, # [out, optional] ReturnLength
]

# https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-logonuserw
advapi32.LogonUserW.restype = BOOL
advapi32.LogonUserW.argtypes = [
    LPCWSTR, # [in] lpszUsername
    LPCWSTR, # [in, optional] lpszDomain
    LPCWSTR, # [in, optional] lpszPassword
    DWORD,   # [in] dwLogonType
    DWORD,   # [in] dwLogonProvider
    PHANDLE  # [out] phToken
]

# https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-lookupprivilegevaluew
advapi32.LookupPrivilegeValueW.restype = BOOL
advapi32.LookupPrivilegeValueW.argtypes = [
    LPCWSTR, # [in, optional] lpSystemName
    LPCWSTR, # [in] lpName
    POINTER(LUID) # [out] lpLuid
]

# https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocesstoken
advapi32.OpenProcessToken.restype = BOOL
advapi32.OpenProcessToken.argtypes = [
    HANDLE, # [in] ProcessHandle,
    DWORD, # [in] DesiredAccess
    PHANDLE, # [out] TokenHandle
]


AdjustTokenPrivileges = advapi32.AdjustTokenPrivileges
LogonUserW = advapi32.LogonUserW
LookupPrivilegeValueW = advapi32.LookupPrivilegeValueW
OpenProcessToken = advapi32.OpenProcessToken

# ---------
# From: userenv.dll
# ---------
userenv = WinDLL("userenv")

# https://learn.microsoft.com/en-us/windows/win32/api/userenv/nf-userenv-loaduserprofilew
userenv.LoadUserProfileW.restype = BOOL
userenv.LoadUserProfileW.argtypes = [
    HANDLE, # [in] hToken
    POINTER(PROFILEINFO) # [in, out] lpProfileInfo
]

# https://learn.microsoft.com/en-us/windows/win32/api/userenv/nf-userenv-unloaduserprofile
userenv.UnloadUserProfile.restype = BOOL
userenv.UnloadUserProfile.argtype = [
    HANDLE, # [in] hToken
    HANDLE, # [in] hProfile
]

LoadUserProfileW = userenv.LoadUserProfileW
UnloadUserProfile = userenv.UnloadUserProfile

# =================================

TOKEN_ADJUST_PRIVILEGES = 0x0020
SE_PRIVILEGE_ENABLED    = 0x00000002
SE_PRIVILEGE_REMOVED    = 0x00000004
# Ref: https://learn.microsoft.com/en-us/windows/win32/secauthz/privilege-constants
SE_BACKUP_NAME           = "SeBackupPrivilege"
SE_RESTORE_NAME          = "SeRestorePrivilege"
# Prevents displaying of messages
PI_NOUI = 0x00000001
# Constant values (ref: https://learn.microsoft.com/en-us/windows/win32/secauthn/logonuserexexw)
LOGON32_PROVIDER_DEFAULT  = 0
LOGON32_LOGON_INTERACTIVE = 2

def adjust_privileges(privilege_names: list[str], enable: bool) -> None:
    proc_token = HANDLE(0)
    if not OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, byref(proc_token)):
        raise WinError()

    token_privileges = TOKEN_PRIVILEGES.allocate(len(privilege_names))
    privs_array = token_privileges.privileges_array()
    for i, name in enumerate(privilege_names):
        if not LookupPrivilegeValueW(None, name, byref(privs_array[i].Luid)):
            CloseHandle(proc_token)
            raise WinError()
        privs_array[i].Attributes = SE_PRIVILEGE_ENABLED if enable else SE_PRIVILEGE_REMOVED

    if not AdjustTokenPrivileges(proc_token, False, byref(token_privileges), ctypes.sizeof(token_privileges), None, None):
        CloseHandle(proc_token)
        raise WinError()
    
    CloseHandle(proc_token)

@contextmanager
def grant_privilege_context(privilege_names: list[str]) -> Generator[None, None, None]:
    try:
        adjust_privileges(privilege_names, True)
        yield
    finally:
        adjust_privileges(privilege_names, False)
            
def run() -> None:
    username = "jobuser"
    password = "arandom12@!"

    print("logon...")
    logon_token = HANDLE(0)
    if not LogonUserW(
        username,
        None,
        password,
        LOGON32_LOGON_INTERACTIVE,
        LOGON32_PROVIDER_DEFAULT,
        byref(logon_token)
    ):
        raise WinError()

    print("Loading user profile...")

    # "The calling process must have the SE_RESTORE_NAME and SE_BACKUP_NAME privileges"
    with grant_privilege_context([SE_BACKUP_NAME,SE_RESTORE_NAME]):
        # Note: As per https://learn.microsoft.com/en-us/windows/win32/api/userenv/nf-userenv-loaduserprofilew#remarks
        # the caller must *be* an Administrator or the LocalSystem account.
        pi = PROFILEINFO()
        pi.dwSize = ctypes.sizeof(PROFILEINFO)
        pi.lpUserName = username
        pi.dwFlags = PI_NOUI # Prevents displaying of messages

        if not LoadUserProfileW(logon_token, byref(pi)):
            raise WinError()
        
    print("Unloading user profile...")

    if not UnloadUserProfile(logon_token, pi.hProfile):
        raise WinError()

    print("Done")

if __name__ == "__main__":
    run()