
import platform
from subprocess import (
    CREATE_NEW_CONSOLE,
    Popen,
    list2cmdline,
    Handle
)
from typing import Any
from _win_user import WindowsSessionUserWithToken
from _win32api_helpers import (
    environment_block_for_user_context,
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

import logging
logger = logging.getLogger()

if platform.python_implementation() != "CPython":
    raise RuntimeError(f"Not compatible with the {platform.python_implementation} of Python. Please use CPython.")

CREATE_UNICODE_ENVIRONMENT = 0x400

class PopenWindowsAsLogon(Popen):
    def __init__(self, *args: Any, user: WindowsSessionUserWithToken, **kwargs: Any) -> None:
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

        with environment_block_for_user_context(self.user.logon_token) as env_ptr:
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
            except Exception as e:
                logger.info("Exception!", str(e))
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
