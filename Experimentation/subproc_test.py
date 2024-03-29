
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
import os

logger = logging.getLogger()

popen_instance: Optional[PopenWindowsAsLogon] = None

def run() -> None:
    global popen_instance
    
    username = "jobuser"
    password = "arandom12@!"

    command = [
        #r"C:\Windows\System32\nvidia-smi.exe",
        r"C:\Windows\System32\whoami.exe"
        # r"C:\Program Files\Python312\python.exe",
        # "-c",
        # "import time; print('Sleeping...'); time.sleep(600)"
    ]

    user = WindowsSessionUserWithToken(username=username, password=password)

    popen_args: dict[str, Any] = dict(
        stdin=DEVNULL,
        stdout=PIPE,
        stderr=STDOUT,
        encoding="utf-8",
        start_new_session=True,
        # TODO: Does CREATE_NEW_CONSOLE require special handling by us??
        creationflags=CREATE_NEW_PROCESS_GROUP,
        args=command
    )

    logger.debug("Creating Popen instance")

    popen_instance = PopenWindowsAsLogon(
        user=user,
        **popen_args,
    )

    if popen_instance.stdout is not None:
        try:
            for line in iter(popen_instance.stdout.readline, ""):
                logger.info(f"[STDOUT] {line.rstrip(os.linesep)}")
                print(f"[STDOUT] {line.rstrip(os.linesep)}")
        except ValueError as e:
            if 'I/O operation on closed file.' == str(e):
                logger.info("Stdout closed")
                print("stdout closed")
            else:
                raise
    else:
        logger.info("No stdout")

    logger.info(f"Subprocess exit code is {popen_instance.wait()}")
    print("exited")

    del popen_instance

    user.close()

    logger.info("")