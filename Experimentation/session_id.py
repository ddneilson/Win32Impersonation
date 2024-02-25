import ctypes
from ctypes import wintypes

kernel32 = ctypes.WinDLL("Kernel32")

def get_process_and_session_id() -> tuple[int, int]:
    pid = kernel32.GetCurrentProcessId()
    session_id = wintypes.DWORD()
    success = kernel32.ProcessIdToSessionId(
        pid, # [in]
        ctypes.byref(session_id) # [out]
    )
    if not success:
        raise RuntimeError(f"Failed to get session id! PID={pid}")
    return pid, session_id.value


pid, sess = get_process_and_session_id()
print(f"PID = {pid}, SESSION_ID = {sess}")