
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
    PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
    STARTF_USESHOWWINDOW,
    STARTF_USESTDHANDLES,
    # Structures
    PROCESS_INFORMATION,
    STARTUPINFOEX,
    SIZE_T,
    # Functions
    CloseHandle,
    CreateProcessAsUserW,
    CreateEnvironmentBlock,
    DeleteProcThreadAttributeList,
    DestroyEnvironmentBlock,
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

import os
import logging
logger = logging.getLogger()

if platform.python_implementation() != "CPython":
    raise RuntimeError(f"Not compatible with the {platform.python_implementation} of Python. Please use CPython.")

CREATE_UNICODE_ENVIRONMENT   = 0x00000400
EXTENDED_STARTUPINFO_PRESENT = 0x00080000

SW_HIDE = 0

def allocate_attribute_list(startup_info: STARTUPINFOEX, num_attributes: int) -> None:
    # As per https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-initializeprocthreadattributelist#remarks
    # First we call InitializeProcThreadAttributeList with an null attribute list,
    # and it'll tell us how large of a buffer lpAttributeList needs to be.
    # This will always return False, so we don't check return code.
    lp_size = SIZE_T(0)
    InitializeProcThreadAttributeList(
        None,
        num_attributes,
        0, # reserved, and must be 0
        byref(lp_size)
    )

    # Allocate the desired buffer
    buffer = (c_byte * lp_size.value)()
    startup_info.lpAttributeList = ctypes_cast(pointer(buffer) , c_void_p)

    # Second call to actually initialize the buffer
    if not InitializeProcThreadAttributeList(
        startup_info.lpAttributeList,
        num_attributes,
        0, # reserved, and must be 0
        byref(lp_size)
    ):
        raise WinError()

def inherit_handles(startup_info: STARTUPINFOEX, handles: tuple[int]) -> Array:
    handles_list = (HANDLE * len(handles))()
    for i,h in enumerate(handles):
        handles_list[i] = h
    if not UpdateProcThreadAttribute(
        startup_info.lpAttributeList,
        0, # reserved and must be 0
        PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
        byref(handles_list),
        sizeof(handles_list),
        None, # reserved and must be null
        None # reserved and must be null
    ):
        raise WinError()
    return handles_list

class PopenWindowsAsLogon(Popen):

    def __init__(
        self,
        *args: Any,
        user: WindowsSessionUserWithToken,
        **kwargs: Any
    ) -> None:
        self.user = user
        super(PopenWindowsAsLogon, self).__init__(*args, **kwargs)
    
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
        si = STARTUPINFOEX()
        si.StartupInfo.cb = sizeof(STARTUPINFOEX)
        pi = PROCESS_INFORMATION()
        creationflags |= EXTENDED_STARTUPINFO_PRESENT

        use_std_handles = -1 not in (p2cread, c2pwrite, errwrite)
        if use_std_handles:
            si.StartupInfo.hStdInput = int(p2cread)
            si.StartupInfo.hStdOutput = int(c2pwrite)
            si.StartupInfo.hStdError = int(errwrite)
            si.StartupInfo.dwFlags |= STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW
            # Ensure that the console window is hidden
            si.StartupInfo.wShowWindow = SW_HIDE
        
        # 
        handles_to_inherit = tuple(int(h) for h in (p2cread, c2pwrite, errwrite) if h != -1)
        import sys
        print(handles_to_inherit)
        allocate_attribute_list(si, len(handles_to_inherit))
        # Note: We must ensure that 'handles_list' must persist until the
        # attribute list is destroyed using DeleteProcThreadAttributeList 
        handles_list = inherit_handles(si, handles_to_inherit)

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
            # TODO - Integrity level
            #   https://github.com/chromium/chromium/blob/fd8a8914ca0183f0add65ae55f04e287543c7d4a/base/process/process_info_win.cc#L30

            if not CreateProcessAsUserW(
                self.user.logon_token,
                executable,
                cmdline,
                None,
                None,
                True,
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

            try:
                if not DestroyEnvironmentBlock(env_ptr):
                    raise WinError()
            finally:
                DeleteProcThreadAttributeList(si.lpAttributeList)
                pass
        
        # Retain the process handle, but close the thread handle
        CloseHandle(pi.hThread)

        logger.info("Passed close")

        self._child_created = True
        self.pid = pi.dwProcessId
        self._handle = Handle(pi.hProcess)

        logger.info("Exiting: _execute_child")
