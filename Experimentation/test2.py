from subprocess import DEVNULL, PIPE, STDOUT, CREATE_NEW_PROCESS_GROUP, CREATE_NEW_CONSOLE

import sys
from typing import Any
from contextlib import contextmanager

import ctypes
from ctypes import wintypes
from ctypes.wintypes import BOOL, LPCWSTR, LPWSTR, DWORD, PHANDLE, HANDLE, LPVOID
from subprocess import Handle, list2cmdline, Popen  # type: ignore

advapi32 = ctypes.WinDLL("advapi32")
kernel32 = ctypes.WinDLL("kernel32")
userenv = ctypes.WinDLL("userenv")

# Constants
LOGON_WITH_PROFILE   = 0x00000001
STARTF_USESTDHANDLES = 0x00000100

SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x00000001
SE_PRIVILEGE_ENABLED            = 0x00000002
SE_PRIVILEGE_REMOVED            = 0x00000004
SE_PRIVILEGE_USED_FOR_ACCESS    = 0x80000000

SE_INCREASE_QUOTA_NAME     = "SeIncreaseQuotaPrivilege"
SE_ASSIGNPRIMARYTOKEN_NAME = "SeAssignPrimaryTokenPrivilege"
SE_TCB_NAME                = "SeTcbPrivilege"

# From https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-token_information_class
TokenPrivileges         = 3
TokenSecurityAttributes = 39

STANDARD_RIGHTS_REQUIRED = 0x0F0000
STANDARD_RIGHTS_READ     = 0x020000
STANDARD_RIGHTS_WRITE    = STANDARD_RIGHTS_READ
STANDARD_RIGHTS_EXECUTE  = STANDARD_RIGHTS_READ
STANDARD_RIGHTS_ALL      = 0x1F0000

# Token access privileges (ref: https://learn.microsoft.com/en-us/windows/win32/secauthz/access-rights-for-access-token-objects)
TOKEN_ASSIGN_PRIMARY    = 0x0001
TOKEN_DUPLICATE         = 0x0002
TOKEN_IMPERSONATE       = 0x0004
TOKEN_QUERY             = 0x0008
TOKEN_QUERY_SOURCE      = 0x0010
TOKEN_ADJUST_PRIVILEGES = 0x0020
TOKEN_ADJUST_GROUPS     = 0x0040
TOKEN_ADJUST_DEFAULT    = 0x0080
TOKEN_ADJUST_SESSIONID  = 0x0100
TOKEN_READ              = STANDARD_RIGHTS_READ | TOKEN_QUERY
TOKEN_WRITE             = STANDARD_RIGHTS_WRITE | TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT
TOKEN_ALL_ACCESS        = (
    STANDARD_RIGHTS_ALL |
    TOKEN_ASSIGN_PRIMARY |
    TOKEN_DUPLICATE |
    TOKEN_IMPERSONATE | 
    TOKEN_QUERY |
    TOKEN_QUERY_SOURCE | 
    TOKEN_ADJUST_PRIVILEGES |
    TOKEN_ADJUST_GROUPS |
    TOKEN_ADJUST_DEFAULT |
    TOKEN_ADJUST_SESSIONID
)

# Structures
# https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-startupinfoa
class STARTUPINFO(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("lpReserved", wintypes.LPWSTR),
        ("lpDesktop", wintypes.LPWSTR),
        ("lpTitle", wintypes.LPWSTR),
        ("dwX", wintypes.DWORD),
        ("dwY", wintypes.DWORD),
        ("dwXSize", wintypes.DWORD),
        ("dwYSize", wintypes.DWORD),
        ("dwXCountChars", wintypes.DWORD),
        ("dwYCountChars", wintypes.DWORD),
        ("dwFillAttribute", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("wShowWindow", wintypes.WORD),
        ("cbReserved2", wintypes.WORD),
        ("lpReserved2", ctypes.POINTER(wintypes.BYTE)),
        ("hStdInput", wintypes.HANDLE),
        ("hStdOutput", wintypes.HANDLE),
        ("hStdError", wintypes.HANDLE),
    ]


# https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-process_information
class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess", wintypes.HANDLE),
        ("hThread", wintypes.HANDLE),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId", wintypes.DWORD),
    ]

# https://learn.microsoft.com/en-us/windows/win32/api/profinfo/ns-profinfo-profileinfoa
class PROFILEINFO(ctypes.Structure):
    _fields_ = [
        ('dwSize', wintypes.DWORD),
        ('dwFlags', wintypes.DWORD),
        ('lpUserName', wintypes.LPWSTR),
        ('lpProfilePath', wintypes.LPWSTR),
        ('lpDefaultPath', wintypes.LPWSTR),
        ('lpServerName', wintypes.LPWSTR),
        ('lpPolicyPath', wintypes.LPWSTR),
        ('hprofile', wintypes.HANDLE)
    ]

# https://learn.microsoft.com/en-us/windows/win32/api/wtypesbase/ns-wtypesbase-security_attributes
class SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ('nLength', wintypes.DWORD),
        ('lpSecurityDescriptor', wintypes.LPVOID),
        ('bInheritHandle', wintypes.BOOL)
    ]

# https://learn.microsoft.com/en-us/windows/win32/api/ntdef/ns-ntdef-luid
class LUID(ctypes.Structure):
    _fields_ = [
        ('LowPart', wintypes.ULONG),
        ('HighPart', wintypes.LONG)
    ]

class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ('Luid', LUID),
        ('Attributes', wintypes.DWORD)
    ]

# https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_privileges
class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [
        ('PrivilegeCount', wintypes.DWORD),
        # Note: To use
        #   ctypes.cast(ctypes.byref(self.Privileges), ctypes.POINTER(LUID_AND_ATTRIBUTES * self.PrivilegeCount)).contents
        ('Privileges', LUID_AND_ATTRIBUTES * 0)
    ]

kernel32.CloseHandle.restype = BOOL
kernel32.CloseHandle.argtypes = [HANDLE]

# https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getcurrentprocess
kernel32.GetCurrentProcess.restype = HANDLE
kernel32.GetCurrentProcess.argtypes = []

advapi32.LogonUserW.restype = BOOL
advapi32.LogonUserW.argtypes = [LPCWSTR, LPCWSTR, LPCWSTR, DWORD, DWORD, PHANDLE]
advapi32.CreateProcessWithTokenW.restype = BOOL
advapi32.CreateProcessWithTokenW.argtypes = [HANDLE, DWORD, LPCWSTR, LPWSTR, DWORD, LPVOID, LPCWSTR, ctypes.POINTER(STARTUPINFO), ctypes.POINTER(PROCESS_INFORMATION)]

# https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-lookupprivilegevaluew
advapi32.LookupPrivilegeValueW.restype = BOOL
advapi32.LookupPrivilegeValueW.argtypes = [
    LPCWSTR, # [in, optional] lpSystemName
    LPCWSTR, # [in] lpName
    ctypes.POINTER(LUID) # [out] lpLuid
]

# https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-adjusttokenprivileges
advapi32.AdjustTokenPrivileges.restype = BOOL
advapi32.AdjustTokenPrivileges.argtypes = [
    HANDLE, # [in] TokenHandle
    BOOL, # [in] DisableAllPrivileges
    ctypes.POINTER(TOKEN_PRIVILEGES), # [in, optional] NewState
    DWORD, # [in] BufferLength
    ctypes.POINTER(TOKEN_PRIVILEGES), # [out, optional] PreviousState
    ctypes.POINTER(wintypes.DWORD), # [out, optional] ReturnLength
]

# https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw
advapi32.CreateProcessAsUserW.restype = BOOL
advapi32.CreateProcessAsUserW.argtypes = [
    HANDLE, # [in, optional] hToken
    LPCWSTR, # [in, optional] lpApplicationName
    LPWSTR, # [in, out, optional] lpCommandLine
    ctypes.POINTER(SECURITY_ATTRIBUTES), # [in, optional] lpProcessAttributes
    ctypes.POINTER(SECURITY_ATTRIBUTES), # [in, optional] lpThreadAttributes
    BOOL, # [in] bInheritHandles
    DWORD, # [in] dwCreationFlags
    LPVOID, # [in, optional] lpEnvironment
    LPCWSTR, # [in, optional] lpCurrentDirectory
    ctypes.POINTER(STARTUPINFO), # [in] lpStartupInfo
    ctypes.POINTER(PROCESS_INFORMATION) # [out] lpProcessInformation
]

# https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-gettokeninformation
advapi32.GetTokenInformation.restype = BOOL
advapi32.GetTokenInformation.argtypes = [
    HANDLE, # [in] TokenHandle
    DWORD, # [in] TokenInformationClass (actually an enum)
    LPVOID, # [out, optional] TokenInformation
    DWORD, # [in] TokenInformationLength
    ctypes.POINTER(DWORD) # [out] ReturnLength
]

advapi32.LookupPrivilegeNameW.restype = BOOL
advapi32.LookupPrivilegeNameW.argtypes = [
    LPCWSTR, # [in, optional] lpSystemName
    ctypes.POINTER(LUID), # [in] lpLuid
    LPWSTR, # [out] lpName
    wintypes.LPDWORD, # [in, out] cchName
]

# https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocesstoken
advapi32.OpenProcessToken.restype = BOOL
advapi32.OpenProcessToken.argtypes = [
    HANDLE, # [in] ProcessHandle,
    DWORD, # [in] DesiredAccess
    ctypes.POINTER(HANDLE), # [out] TokenHandle
]


userenv.LoadUserProfileW.restype = BOOL
userenv.LoadUserProfileW.argtypes = [HANDLE, ctypes.POINTER(PROFILEINFO)]

class PopenWindowsAsUser(Popen):
    """Class to run a process as another user on Windows.
    Derived from Popen, it defines the _execute_child() method to call CreateProcessWithLogonW.
    """

    def __init__(self, logon_token: wintypes.HANDLE, *args: Any, **kwargs: Any):
        """
        Arguments:
            username (str):  Name of user to run subprocess as
            password (str):  Password for username
            args (Any):  Popen constructor args
            kwargs (Any):  Popen constructor kwargs
            https://docs.python.org/3/library/subprocess.html#popen-constructor
        """
        self.logon_token = logon_token
        super(PopenWindowsAsUser, self).__init__(*args, **kwargs)

    def _execute_child(
        self,
        args,
        executable,
        preexec_fn,
        close_fds,
        pass_fds,
        cwd,
        env,
        startupinfo,
        creationflags,
        shell,
        p2cread,
        p2cwrite,
        c2pread,
        c2pwrite,
        errread,
        errwrite,
        restore_signals,
        start_new_session,
        *additional_args,
        **kwargs,
    ):
        """Execute program (MS Windows version).
        Calls CreateProcessWithLogonW to run a process as another user.
        """

        assert not pass_fds, "pass_fds not supported on Windows."

        commandline = args if isinstance(args, str) else list2cmdline(args)

        # Initialize structures
        si = STARTUPINFO()
        si.cb = ctypes.sizeof(STARTUPINFO)
        pi = PROCESS_INFORMATION()

        si.hStdInput = int(p2cread)
        si.hStdOutput = int(c2pwrite)
        si.hStdError = int(errwrite)
        si.dwFlags |= STARTF_USESTDHANDLES

        # CreateProcess* may modify the commandline, so copy it to a mutable buffer.
        cmdline = ctypes.create_unicode_buffer(commandline)

        # print(pi)
        # print(cmdline)
        # print(self.logon_token)
        # print(executable)
        # print(commandline)
        # print(env)
        # print(cwd)

        # print("SI=")
        # for f in si._fields_:
        #     print(f[0], getattr(si, f[0]))

        # print("PI=")
        # for f in pi._fields_:
        #     print(f[0], getattr(pi, f[0]))


        # https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw
        # https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw
        #result = advapi32.CreateProcessWithTokenW(
        result = advapi32.CreateProcessAsUserW(
            self.logon_token,
            executable,
            cmdline,
            None,
            None,
            True,
            creationflags,
            env,
            cwd,
            ctypes.byref(si),
            ctypes.byref(pi),
        )

        if not result:
            raise ctypes.WinError()

        # Child is launched. Close the parent's copy of those pipe
        # handles that only the child should have open.
        self._close_pipe_fds(p2cread, p2cwrite, c2pread, c2pwrite, errread, errwrite)

        # Retain the process handle, but close the thread handle
        kernel32.CloseHandle(pi.hThread)

        self._child_created = True
        self.pid = pi.dwProcessId
        self._handle = Handle(pi.hProcess)

@contextmanager
def logon_context(username: str, password: str) -> HANDLE:
    # Constant values (ref: https://learn.microsoft.com/en-us/windows/win32/secauthn/logonuserexexw)
    LOGON32_LOGON_INTERACTIVE = 2
    LOGON32_LOGON_BATCH = 4
    LOGON32_LOGON_SERVICE = 5

    LOGON32_PROVIDER_DEFAULT = 0

    hToken = wintypes.HANDLE(0)
    success = advapi32.LogonUserW(
        username,   # username[in]
        None,          # domain[in]
        password, # password[out]
        LOGON32_LOGON_BATCH, #LOGON32_LOGON_SERVICE, # [in]
        LOGON32_PROVIDER_DEFAULT, # [in]
        ctypes.byref(hToken) # [out]
    )
    if not success:
        raise ctypes.WinError()

    yield hToken

    # https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-closehandle
    if not kernel32.CloseHandle(hToken):
        raise ctypes.WinError()

def load_profile(username: str, logon_token: HANDLE) -> None:
    pi = PROFILEINFO()
    pi.dwSize = ctypes.sizeof(PROFILEINFO)
    pi.lpUserName = username
    if not userenv.LoadUserProfileW(logon_token, ctypes.byref(pi)):
        raise ctypes.WinError()

def get_token_privileges(logon_token: HANDLE) -> list[LUID_AND_ATTRIBUTES]:
    # Enough space for 32 privileges; hopefully that's enough?
    info_length = ctypes.sizeof(TOKEN_PRIVILEGES) + 64 * ctypes.sizeof(LUID_AND_ATTRIBUTES)
    buffer = (ctypes.c_byte * info_length)()
    tok_privs = ctypes.cast(buffer, ctypes.POINTER(TOKEN_PRIVILEGES))[0]
    return_length = wintypes.DWORD(0)

    if not advapi32.GetTokenInformation(
        logon_token,
        TokenPrivileges,
        ctypes.byref(tok_privs),
        info_length,
        ctypes.byref(return_length)
    ):
        raise ctypes.WinError()

    if return_length.value > info_length:
        raise RuntimeError(f"Make the buffer bigger and try again! -- {return_length.value}")

    # print(info_length, return_length.value)
    # array_length = (return_length.value - ctypes.sizeof(TOKEN_PRIVILEGES)) // ctypes.sizeof(LUID_AND_ATTRIBUTES)
    # print(array_length)
    # print(tok_privs.PrivilegeCount)

    return ctypes.cast(
        ctypes.byref(tok_privs.Privileges),
        ctypes.POINTER(LUID_AND_ATTRIBUTES * tok_privs.PrivilegeCount)
    ).contents

def lookup_privilege_name(luid: LUID) -> str:
    name = ctypes.create_unicode_buffer(128)
    bufferlen = ctypes.sizeof(name)
    namelen = wintypes.DWORD(bufferlen)
    if not advapi32.LookupPrivilegeNameW(
        None,
        ctypes.byref(luid),
        name,
        ctypes.byref(namelen)
    ):
        raise ctypes.WinError()
    
    if namelen.value > bufferlen:
        raise RuntimeError(f"Make the buffer bigger and try again! -- {namelen.value}")
    
    return name.value

def luid_attribute_to_str(attr: int) -> str:
    ret = []
    if attr & SE_PRIVILEGE_ENABLED_BY_DEFAULT:
        ret.append("ENABLED_BY_DEFAULT")
    if attr & SE_PRIVILEGE_ENABLED:
        ret.append("ENABLED")
    if attr & SE_PRIVILEGE_REMOVED:
        ret.append("REMOVED")
    if attr & SE_PRIVILEGE_USED_FOR_ACCESS:
        ret.append("USED_FOR_ACCESS")
    return hex(attr) + " = " + " | ".join(ret)


def print_token_privs(name: str, token: HANDLE) -> None:
    token_privileges = get_token_privileges(token)
    print(f"Token Privileges for token {name}:")
    for p in token_privileges:
        print(lookup_privilege_name(p.Luid), luid_attribute_to_str(p.Attributes))
    print("---")

# Note: This doesn't actually looking the setting of a privilege.
# It's just looking up the ID of a privilege in the local system;
# LookupPrivilegeValueW returns True if the lookup was successful.
#
# for privilege in (SE_ASSIGNPRIMARYTOKEN_NAME, SE_INCREASE_QUOTA_NAME, SE_TCB_NAME):
#     luid = LUID(0)
#     if advapi32.LookupPrivilegeValueW(None, privilege, ctypes.byref(luid)):
#         print(f"Have {privilege}")
#     else:
#         print(f"Do not have {privilege}")

commands = (
    [
        "nvidia-smi"
    ],
    [
        "whoami"
    ],
    [
        sys.executable,
        r"C:\Users\Administrator\ServiceExperimentation\Exp1\session_id.py"
    ]
)
command = [
    "nvidia-smi"
]
username = "agentuser"
password = "arandom12!@"

proc_token = HANDLE(0)
if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), TOKEN_READ, ctypes.byref(proc_token)):
    raise WinError()

print_token_privs("Process", proc_token)
kernel32.CloseHandle(proc_token)

with logon_context(username, password) as logon_token:
    load_profile(username, logon_token)
    print_token_privs("LogonToken", logon_token)

    for command in commands:
        popen_args: dict[str, Any] = dict(
            stdin=DEVNULL,
            stdout=PIPE,
            stderr=STDOUT,
            encoding="utf-8",
            start_new_session=True,
            creationflags=CREATE_NEW_PROCESS_GROUP | CREATE_NEW_CONSOLE,
            args=command
        )

        popen = PopenWindowsAsUser(
            logon_token,
            **popen_args
        )
        if popen.stdout is not None:
            for line in iter(popen.stdout.readline, ""):
                print(line, end='')

