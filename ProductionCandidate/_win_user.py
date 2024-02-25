from ctypes import WinError
from ctypes.wintypes import HANDLE
from _win32api import PROFILEINFO, CloseHandle, UnloadUserProfile
from _win32api_helpers import logon_user, load_user_profile
from typing import Optional

class WindowsSessionUserWithToken:
    username: str
    logon_token: HANDLE
    _PROFILEINFO: Optional[PROFILEINFO]

    def __init__(self, *, username: str, password: Optional[str]=None, logon_token: Optional[HANDLE]=None) -> None:
        self.username = username
        self._PROFILEINFO = None
        if logon_token:
            self.logon_token = logon_token
        else:
            self.logon_token = logon_user(username, password)
            try:
                self._PROFILEINFO = load_user_profile(username, self.logon_token)
            except WinError:
                CloseHandle(self.logon_token)
                self.logon_token = HANDLE(0)
                raise

    def close(self) -> None:
        if self._PROFILEINFO is not None and not UnloadUserProfile(self.logon_token, self._PROFILEINFO.hProfile):
            # "Before calling UnloadUserProfile you should ensure that all handles to keys that you
            # have opened in the user's registry hive are closed. If you do not close all open 
            # registry handles, the user's profile fails to unload."
            print("Could not unload user profile.")
        CloseHandle(self.logon_token)


