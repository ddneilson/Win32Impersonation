
import platform
from subprocess import (
    CREATE_NEW_CONSOLE,
    Popen,
    list2cmdline,
    Handle
)
from enum import Enum
from typing import Any
from _win_user import WindowsSessionUserWithToken
from _win32api_helpers import (
    environment_block_for_user,
    environment_dict_from_block,
    environment_dict_to_block,
)
from _win32api import (
    # Constants
    STARTF_USESHOWWINDOW,
    STARTF_USESTDHANDLES,
    # Structures
    PROCESS_INFORMATION,
    STARTUPINFO,
    # Functions
    CloseHandle,
    CreateProcessAsUserW,
)
from ctypes import (
    byref,
    create_unicode_buffer,
    sizeof,
    WinError
)

import os
import logging
logger = logging.getLogger()

if platform.python_implementation() != "CPython":
    raise RuntimeError(f"Not compatible with the {platform.python_implementation} of Python. Please use CPython.")

CREATE_UNICODE_ENVIRONMENT = 0x400


class BaseEnvironment(Enum):
        TARGET_USER = 0
        """Supplied environment variables supercede target user default environment"""
        NONE = 2
        """Supplied environment variables are the only environment variables."""
        INHERIT = 1
        """Supplied environment variables supercede inherited environment variables of current process"""

class PopenWindowsAsLogon(Popen):

    _base_environment: BaseEnvironment = BaseEnvironment.TARGET_USER

    def __init__(
        self,
        *args: Any,
        user: WindowsSessionUserWithToken,
        base_environment: BaseEnvironment = BaseEnvironment.TARGET_USER,
        **kwargs: Any
    ) -> None:
        self._base_environment = base_environment
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

        # Initialize structures
        si = STARTUPINFO()
        si.cb = sizeof(STARTUPINFO)
        pi = PROCESS_INFORMATION()

        use_std_handles = -1 not in (p2cread, c2pwrite, errwrite)
        if use_std_handles:
            si.hStdInput = int(p2cread)
            si.hStdOutput = int(c2pwrite)
            si.hStdError = int(errwrite)
            si.dwFlags |= STARTF_USESTDHANDLES
        
        # if creationflags & CREATE_NEW_CONSOLE:
        #     si.dwFlags |= STARTF_USESHOWWINDOW
        #     # Ref: https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-showwindow
        #     si.wShowWindow = 0 # SW_HIDE

        # CreateProcess* may modify the commandline, so copy it to a mutable buffer.
        cmdline = create_unicode_buffer(commandline)

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

        # TODO - How do we cleanup the environment block?
        #  If we Destroy it before the subprocess has exited then we get a hard crash
        #  in ntdll.dll

        base_env: dict[str, str] = {}
        if self._base_environment == BaseEnvironment.TARGET_USER:
            env_ptr = environment_block_for_user(self.user.logon_token)
            base_env = environment_dict_from_block(env_ptr)
        elif self._base_environment == BaseEnvironment.INHERIT:
            base_env = dict(os.environ)
        elif self._base_environment == BaseEnvironment.NONE:
            base_env = {}
        else:
            raise NotImplementedError(f"base_environment of {self._base_environment.value} not implemented")
        
        merged_env = base_env.copy()
        if env:
            merged_env.update(env)
        # Sort env vars by keys
        merged_env = {key: merged_env[key] for key in sorted(merged_env.keys())}
        env_ptr = environment_dict_to_block(merged_env)


        logger.info("Starting!")
        try:
            if not CreateProcessAsUserW(
                self.user.logon_token,
                executable,
                cmdline,
                None,
                None,
                True,
                creationflags | CREATE_UNICODE_ENVIRONMENT,
                env_ptr,
                cwd,
                byref(si),
                byref(pi),
            ):
                raise WinError()
            logger.info("Process started")
        finally:
            # Child is launched. Close the parent's copy of those pipe
            # handles that only the child should have open.
            logger.info("Closing pipe fds")
            self._close_pipe_fds(p2cread, p2cwrite, c2pread, c2pwrite, errread, errwrite)
            logger.info("pipe fds closed")

        
        # Retain the process handle, but close the thread handle
        if pi.hThread != 0:
             CloseHandle(pi.hThread)

        logger.info("Passed close")

        self._child_created = True
        self.pid = pi.dwProcessId
        self._handle = Handle(pi.hProcess)

        logger.info("Exiting: _execute_child")
