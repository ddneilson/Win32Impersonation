from _win32api import (
    # Constants
    TOKEN_ADJUST_PRIVILEGES,
    LOGON32_LOGON_INTERACTIVE,
    LOGON32_PROVIDER_DEFAULT,
    PI_NOUI,
    # Structures
    LUID,
    PROFILEINFO,
    SE_BACKUP_NAME,
    SE_PRIVILEGE_ENABLED,
    SE_PRIVILEGE_REMOVED,
    SE_RESTORE_NAME,
    TOKEN_PRIVILEGES,
    # Functions
    AdjustTokenPrivileges,
    CloseHandle,
    CreateEnvironmentBlock,
    DestroyEnvironmentBlock,
    GetCurrentProcess,
    LogonUserW,
    LookupPrivilegeValueW,
    LoadUserProfileW,
    OpenProcessToken,
    UnloadUserProfile
)
from ctypes import (
    WinError,
    byref,
    c_void_p,
    sizeof,
)
from ctypes.wintypes import (
    HANDLE
)
from contextlib import contextmanager
from typing import Generator, Optional


def logon_user(username: str, password: str) -> HANDLE:
    hToken = HANDLE(0)
    if not LogonUserW(
        username,
        None, # TODO - domain handling
        password,
        LOGON32_LOGON_INTERACTIVE,
        LOGON32_PROVIDER_DEFAULT,
        byref(hToken)
    ):
        raise WinError()

    return hToken

@contextmanager
def logon_user_context(username: str, password: str) -> Generator[HANDLE, None, None]:
    hToken: Optional[HANDLE] = None
    try:
        hToken = logon_user(username, password)
        yield hToken
    finally:
        if hToken is not None and not CloseHandle(hToken):
            raise WinError()

def environment_block_for_user(logon_token: HANDLE) -> c_void_p:
    environment = c_void_p()
    if not CreateEnvironmentBlock(byref(environment), logon_token, False):
        raise WinError()
    return environment

@contextmanager
def environment_block_for_user_context(logon_token: HANDLE) -> Generator[c_void_p, None, None]:
    # WARNING! DO NOT USE THIS -- If the EnvironmentBlock is destroyed before the process using it
    # has exited then we'll get an error in ntdll.dll
    lp_environment: Optional[c_void_p] = None
    try:
        lp_environment = environment_block_for_user(logon_token)
        yield lp_environment
    finally:
        if lp_environment is not None and not DestroyEnvironmentBlock(lp_environment):
            raise WinError()

def adjust_privileges(privilege_names: list[str], enable: bool) -> None:
    proc_token = HANDLE(0)
    if not OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, byref(proc_token)):
        raise WinEror()

    token_privileges = TOKEN_PRIVILEGES.allocate(len(privilege_names))
    privs_array = token_privileges.privileges_array()
    for i, name in enumerate(privilege_names):
        if not LookupPrivilegeValueW(None, name, byref(privs_array[i].Luid)):
            CloseHandle(proc_token)
            raise WinError()
        privs_array[i].Attributes = SE_PRIVILEGE_ENABLED if enable else SE_PRIVILEGE_REMOVED

    if not AdjustTokenPrivileges(proc_token, False, byref(token_privileges), sizeof(token_privileges), None, None):
        CloseHandle(proc_token)
        raise WinEror()
    
    CloseHandle(proc_token)

@contextmanager
def grant_privilege_context(privilege_names: list[str]) -> Generator[None, None, None]:
    try:
        adjust_privileges(privilege_names, True)
        yield
    finally:
        adjust_privileges(privilege_names, False)

def load_user_profile(username: str, logon_token: HANDLE) -> PROFILEINFO:
    # TODO - Handle Roaming Profiles
    # As per https://learn.microsoft.com/en-us/windows/win32/api/userenv/nf-userenv-loaduserprofilew#remarks
    # "Services and applications that call LoadUserProfile should check to see if the user has a roaming profile. ..."

    # "The calling process must have the SE_RESTORE_NAME and SE_BACKUP_NAME privileges"
    with grant_privilege_context([SE_BACKUP_NAME,SE_RESTORE_NAME]):
        # Note: As per https://learn.microsoft.com/en-us/windows/win32/api/userenv/nf-userenv-loaduserprofilew#remarks
        # the caller must *be* an Administrator or the LocalSystem account.
        pi = PROFILEINFO()
        pi.dwSize = sizeof(PROFILEINFO)
        pi.lpUserName = username
        pi.dwFlags = PI_NOUI # Prevents displaying of messages

        if not LoadUserProfileW(logon_token, byref(pi)):
            raise WinError()

@contextmanager
def user_profile_context(username: str, logon_token: HANDLE) -> Generator[PROFILEINFO, None, None]:
    profile_info: Optional[PROFILE_INFO] = None
    try:
        profile_info = load_profiload_user_profile(username, logon_token)
        yield profile_info
    finally:
        if profile_info is not None and not UnloadUserProfile(logon_token, profile_info.hProfile):
            # "Before calling UnloadUserProfile you should ensure that all handles to keys that you
            # have opened in the user's registry hive are closed. If you do not close all open 
            # registry handles, the user's profile fails to unload."
            print("Could not unload user profile.")