
import platform
from subprocess import (
    CREATE_NEW_CONSOLE,
    Popen,
    list2cmdline,
    Handle
)
from enum import Enum
from typing import Any, Optional, cast
from _win_user import WindowsSessionUserWithToken
from _win32api_helpers import (
    environment_block_for_user,
    environment_block_from_dict,
    environment_block_to_dict,
)
from _win32api import (
    # Constants
    LOGON_WITH_PROFILE,
    PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
    STARTF_USESHOWWINDOW,
    STARTF_USESTDHANDLES,
    TokenPrimary,
    SecurityImpersonation,
    # Structures
    PROCESS_INFORMATION,
    STARTUPINFO,
    SIZE_T,
    # Functions
    CloseHandle,
    CreateProcessWithTokenW,
    CreateEnvironmentBlock,
    DestroyEnvironmentBlock,
    DuplicateTokenEx,
    InitializeProcThreadAttributeList,
    UpdateProcThreadAttribute
)
from ctypes import (
    Array,
    addressof,
    byref,
    cast as ctypes_cast,
    create_unicode_buffer,
    c_byte,
    c_void_p,
    c_wchar_p,
    pointer,
    sizeof,
    WinError
)
from ctypes.wintypes import HANDLE

import win32security
import ntsecuritycon
import win32service
import win32process
import win32api
import win32con
import pywintypes

import os
import logging
logger = logging.getLogger()

if platform.python_implementation() != "CPython":
    raise RuntimeError(f"Not compatible with the {platform.python_implementation} of Python. Please use CPython.")

CREATE_UNICODE_ENVIRONMENT   = 0x00000400

SW_HIDE = 0

### -- The following copied from saltstack
# https://github.com/saltstack/salt/blob/127a32e4806e1e186b80afaf60762ebcbc211ef5/salt/platform/win.py#L1074
# License: Apache-2.0

WINSTA_ALL = (
    win32con.WINSTA_ACCESSCLIPBOARD
    | win32con.WINSTA_ACCESSGLOBALATOMS
    | win32con.WINSTA_CREATEDESKTOP
    | win32con.WINSTA_ENUMDESKTOPS
    | win32con.WINSTA_ENUMERATE
    | win32con.WINSTA_EXITWINDOWS
    | win32con.WINSTA_READATTRIBUTES
    | win32con.WINSTA_READSCREEN
    | win32con.WINSTA_WRITEATTRIBUTES
    | win32con.DELETE
    | win32con.READ_CONTROL
    | win32con.WRITE_DAC
    | win32con.WRITE_OWNER
)

DESKTOP_ALL = (
    win32con.DESKTOP_CREATEMENU
    | win32con.DESKTOP_CREATEWINDOW
    | win32con.DESKTOP_ENUMERATE
    | win32con.DESKTOP_HOOKCONTROL
    | win32con.DESKTOP_JOURNALPLAYBACK
    | win32con.DESKTOP_JOURNALRECORD
    | win32con.DESKTOP_READOBJECTS
    | win32con.DESKTOP_SWITCHDESKTOP
    | win32con.DESKTOP_WRITEOBJECTS
    | win32con.DELETE
    | win32con.READ_CONTROL
    | win32con.WRITE_DAC
    | win32con.WRITE_OWNER
)


def set_user_perm(obj, perm, sid):
    """
    Set an object permission for the given user sid
    """
    print("Setting permissions for SID: ", str(sid))
    info = (
        win32security.OWNER_SECURITY_INFORMATION
        | win32security.GROUP_SECURITY_INFORMATION
        | win32security.DACL_SECURITY_INFORMATION
    )
    sd = win32security.GetUserObjectSecurity(obj, info)
    dacl = sd.GetSecurityDescriptorDacl()
    ace_cnt = dacl.GetAceCount()
    found = False
    for idx in range(0, ace_cnt):
        (aceType, aceFlags), ace_mask, ace_sid = dacl.GetAce(idx)
        ace_exists = (
            aceType == ntsecuritycon.ACCESS_ALLOWED_ACE_TYPE
            and ace_mask == perm
            and ace_sid == sid
        )
        if ace_exists:
            # If the ace already exists, do nothing
            print("Exists")
            break
    else:
        print("Adding permission")
        dacl.AddAccessAllowedAce(dacl.GetAclRevision(), perm, sid)
        sd.SetSecurityDescriptorDacl(1, dacl, 0)
        win32security.SetUserObjectSecurity(obj, info, sd)


def grant_winsta_and_desktop(th):
    """
    Grant the token's user access to the current process's window station and
    desktop.
    """
    current_sid = win32security.GetTokenInformation(th, win32security.TokenUser)[0]
    # Add permissions for the sid to the current windows station and thread id.
    # This prevents windows error 0xC0000142.
    winsta = win32process.GetProcessWindowStation()
    set_user_perm(winsta, WINSTA_ALL, current_sid)
    desktop = win32service.GetThreadDesktop(win32api.GetCurrentThreadId())
    set_user_perm(desktop, DESKTOP_ALL, current_sid)

## -- END COPY

class PopenWindowsWithToken(Popen):

    def __init__(
        self,
        *args: Any,
        user: WindowsSessionUserWithToken,
        **kwargs: Any
    ) -> None:
        self.user = user
        super(PopenWindowsWithToken, self).__init__(*args, **kwargs)
    
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
        # CreateProcess* may modify the commandline, so copy it to a mutable buffer
        cmdline = create_unicode_buffer(commandline)

        if executable is not None:
            executable = os.fsdecode(executable)

        if cwd is not None:
            cwd = os.fsdecode(cwd)

        # Initialize structures
        si = STARTUPINFO()
        si.cb = sizeof(STARTUPINFO)
        pi = PROCESS_INFORMATION()

        use_std_handles = -1 not in (p2cread, c2pwrite, errwrite)
        if use_std_handles:
            si.hStdInput = int(p2cread)
            si.hStdOutput = int(c2pwrite)
            si.hStdError = int(errwrite)
            si.dwFlags |= STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW
            # Ensure that the console window is hidden
            si.wShowWindow = SW_HIDE

        # Note: This pywintype handle will automatically get closed when the
        # object is GC'd. This is fine for PoC, but not for general use since it'll
        # close the logon token.
        hh = pywintypes.HANDLE(self.user.logon_token.value)

        # A permissions workaround employed by saltstack
        # https://github.com/saltstack/salt/blob/127a32e4806e1e186b80afaf60762ebcbc211ef5/salt/utils/win_runas.py#L164
        # Doesn't smell right to me.
        grant_winsta_and_desktop(hh)

        # print(pi)
        # print(cmdline)
        # print(self.user.logon_token)
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

        # From https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw
        # If the lpEnvironment parameter is NULL, the new process inherits the environment of the calling process.
        # CreateProcessAsUser does not automatically modify the environment block to include environment variables specific to
        # the user represented by hToken. For example, the USERNAME and USERDOMAIN variables are inherited from the calling
        # process if lpEnvironment is NULL. It is your responsibility to prepare the environment block for the new process and
        # specify it in lpEnvironment.

        def _merge_environment(
            user_env: c_void_p, env: dict[str, Optional[str]]
        ) -> c_wchar_p:
            user_env_dict = cast(dict[str, Optional[str]], environment_block_to_dict(user_env))
            user_env_dict.update(**env)
            result = {k: v for k, v in user_env_dict.items() if v is not None}
            return environment_block_from_dict(result)

        env_ptr = environment_block_for_user(self.user.logon_token)
        env_block = env_ptr
        if env:
            env_block = _merge_environment(env_ptr, env)
        else:
            env_block = env_ptr
        env_block = None

        logger.info("Starting!")
        try:
            if not CreateProcessWithTokenW(
                self.user.logon_token,
                LOGON_WITH_PROFILE,
                executable,
                cmdline,
                creationflags | CREATE_UNICODE_ENVIRONMENT,
                env_block,
                cwd,
                byref(si),
                byref(pi),
            ):
                raise WinError()
            logger.info("Process started")
        finally:
            logger.info("Finally block")

            # Child is launched. Close the parent's copy of those pipe
            # handles that only the child should have open.
            logger.info("Closing pipe fds")
            self._close_pipe_fds(p2cread, p2cwrite, c2pread, c2pwrite, errread, errwrite)
            logger.info("pipe fds closed")

            if not DestroyEnvironmentBlock(env_ptr):
                raise WinError()
        
        # Retain the process handle, but close the thread handle
        CloseHandle(pi.hThread)

        logger.info("Passed close")

        self._child_created = True
        self.pid = pi.dwProcessId
        self._handle = Handle(pi.hProcess)

        logger.info("Exiting: _execute_child")
