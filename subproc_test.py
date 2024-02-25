
from _win_logon_popen import PopenWindowsAsLogon
from _win_user import WindowsSessionUserWithToken
from subprocess import (
    DEVNULL,
    PIPE,
    STDOUT,
    CREATE_NEW_PROCESS_GROUP,
    CREATE_NEW_CONSOLE
)
from typing import Any, Optional
import logging

logger = logging.getLogger()

popen_instance: Optional[PopenWindowsAsLogon] = None

def run() -> None:
    global popen_instance
    
    username = "agentuser"
    password = "arandom12!@"

    command = [
        #r"C:\Windows\System32\nvidia-smi.exe",
        r"C:\Windows\System32\whoami.exe"
    ]

    user = WindowsSessionUserWithToken(username=username, password=password)

    popen_args: dict[str, Any] = dict(
        stdin=DEVNULL,
        stdout=PIPE,
        stderr=STDOUT,
        encoding="utf-8",
        start_new_session=True,
        # TODO: Does CREATE_NEW_CONSOLE require special handling by us??
        creationflags=CREATE_NEW_PROCESS_GROUP | CREATE_NEW_CONSOLE,
        args=command
    )

    logger.debug("Creating Popen instance")

    popen_instance = PopenWindowsAsLogon(
        user=user,
        **popen_args,
    )

    if popen_instance.stdout is not None:
        for line in iter(popen_instance.stdout.readline, ""):
            logger.info(line)
    else:
        logger.info("No stdout")

    logger.info(f"Subprocess exit code is {popen_instance.wait()}")

    user.close()