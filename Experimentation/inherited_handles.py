
# Introspects this process to find the handles that it has inherited from its
# parent process.
# Per MS support, the way to accomplish this is with undocumented functionality of the
# NtQueryProcessInformation API.
# That API can be used to obtain a list of all of a process' handles that are
# marked for inheritence. So, you fetch the marked-inheritance handles from both
# this process and the parent process. The handle IDs that appear in both lists
# are the ones that have been inherited to this process from its parent.
#
# Warning: NtQueryProcessInformation is an "undocumented API" and thus its
# functionality and the layout of its datastructures can change between Windows
# versions.

import ctypes
from ctypes import (
    POINTER,
    c_ulong,
    c_ulonglong,
    c_void_p,
)
from ctypes.wintypes import (
    BOOL,
    DWORD,
    HANDLE,
    LONG,
    LPCWSTR,
    PDWORD,
    PHANDLE,
    PULONG,
    ULONG

)
from collections.abc import Sequence

# Ref: https://github.com/winsiderss/systeminformer/blob/e01be6536a74464446687e75b0e34c3988d875d8/phnt/include/ntpsapi.h#L163
ProcessBasicInformation = 0
ProcessHandleCount = 20
ProcessHandleInformation = 51

# Ref: https://ntdoc.m417z.com/process_handle_table_entry_info#handleattributes
OBJ_PROTECT_CLOSE = 0x01
OBJ_INHERIT       = 0x02
OBJ_PERMANENT     = 0x04
OBJ_EXCLUSIVE     = 0x08

# https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights
PROCESS_QUERY_INFORMATION  = 0x0400


# Ref: https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess#process_basic_information
class PROCESS_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = (
        ("ExitStatus", c_ulong),
        ("PebBaseAddress", c_void_p),
        ("AffinityMask", c_ulonglong),
        ("BasePriority", DWORD),
        ("UniqueProcessId", HANDLE),
        ("InheritedFromUniqueProcessId", HANDLE)
    )

# Ref: https://github.com/winsiderss/systeminformer/blob/e01be6536a74464446687e75b0e34c3988d875d8/phnt/include/ntpsapi.h#L643
class PROCESS_HANDLE_TABLE_ENTRY_INFO(ctypes.Structure):
    _fields_ = (
        ("HandleValue", HANDLE),
        ("HandleCount", c_ulonglong),
        ("PointerCount", c_ulonglong),
        ("GrantedAccess", c_ulong),
        ("ObjectTypeIndex", c_ulong),
        ("HandleAttributes", c_ulong),
        ("Reserved", c_ulong)
    )

# Ref: https://github.com/winsiderss/systeminformer/blob/e01be6536a74464446687e75b0e34c3988d875d8/phnt/include/ntpsapi.h#L654
class PROCESS_HANDLE_SNAPSHOT_INFORMATION(ctypes.Structure):
    _fields_ = (
        ("NumberOfHandles", c_ulonglong),
        ("Reserved", c_ulonglong),
        ("Handles", PROCESS_HANDLE_TABLE_ENTRY_INFO * 0)
    )

    @staticmethod
    def allocate_bytes(bytes: int) -> "PROCESS_HANDLE_SNAPSHOT_INFORMATION":
        malloc_buffer = (ctypes.c_byte * bytes)()
        to_return = ctypes.cast(malloc_buffer, POINTER(PROCESS_HANDLE_SNAPSHOT_INFORMATION))[0]
        to_return.NumberOfHandles = 0
        return to_return

    @staticmethod
    def allocate(length: int) -> "PROCESS_HANDLE_SNAPSHOT_INFORMATION":
        malloc_size_in_bytes = ctypes.sizeof(PROCESS_HANDLE_SNAPSHOT_INFORMATION) + 2 * ctypes.sizeof(PROCESS_HANDLE_TABLE_ENTRY_INFO)
        malloc_buffer = (ctypes.c_byte * malloc_size_in_bytes)()
        to_return = ctypes.cast(malloc_buffer, POINTER(PROCESS_HANDLE_SNAPSHOT_INFORMATION))[0]
        to_return.NumberOfHandles = length
        return to_return
    
    def handles_array(self) -> Sequence[PROCESS_HANDLE_TABLE_ENTRY_INFO]:
        return ctypes.cast(
            ctypes.byref(self.Handles),
            ctypes.POINTER(PROCESS_HANDLE_TABLE_ENTRY_INFO * self.NumberOfHandles)
        ).contents
    

# Ref: https://github.com/winsiderss/systeminformer/blob/6df9240dc8b6d42d1e3e428102b2236c161f93bc/phnt/include/ntpsapi.h#L624
class PROCESS_HANDLE_INFORMATION(ctypes.Structure):
    _fields_ = (
        ("HandleCount", c_ulong),
        ("HandleCountHighWatermark", c_ulong),
    )

# https://learn.microsoft.com/en-us/windows/win32/api/ntdef/ns-ntdef-luid
class LUID(ctypes.Structure):
    _fields_ = [
        ('LowPart', ULONG),
        ('HighPart', LONG)
    ]

class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ('Luid', LUID),
        ('Attributes', DWORD)
    ]

# https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_privileges
class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [
        ('PrivilegeCount', DWORD),
        # Note: To use
        #   ctypes.cast(ctypes.byref(self.Privileges), ctypes.POINTER(LUID_AND_ATTRIBUTES * self.PrivilegeCount)).contents
        ('Privileges', LUID_AND_ATTRIBUTES * 0)
    ]

    @staticmethod
    def allocate_bytes(bytes: int) -> "TOKEN_PRIVILEGES":
        malloc_buffer = (ctypes.c_byte * bytes)()
        to_return = ctypes.cast(malloc_buffer, POINTER(TOKEN_PRIVILEGES))[0]
        to_return.PrivilegeCount = 0
        return to_return

    @staticmethod
    def allocate(length: int) -> 'TOKEN_PRIVILEGES':
        malloc_size_in_bytes = ctypes.sizeof(TOKEN_PRIVILEGES) + 2 * ctypes.sizeof(LUID_AND_ATTRIBUTES)
        malloc_buffer = (ctypes.c_byte * malloc_size_in_bytes)()
        token_privs = ctypes.cast(malloc_buffer, POINTER(TOKEN_PRIVILEGES))[0]
        token_privs.PrivilegeCount = length
        return token_privs
    
    def privileges_array(self) -> Sequence[LUID_AND_ATTRIBUTES]:
        return ctypes.cast(
            ctypes.byref(self.Privileges),
            ctypes.POINTER(LUID_AND_ATTRIBUTES * self.PrivilegeCount)
        ).contents

kernel32 = ctypes.WinDLL("kernel32")
# https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getcurrentprocess
kernel32.GetCurrentProcess.restype = HANDLE
kernel32.GetCurrentProcess.argtypes = []
# https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getprocessid
kernel32.GetProcessId.restype = DWORD
kernel32.GetProcessId.argtypes = [
    HANDLE, # [in] Process
]
# https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-closehandle
kernel32.CloseHandle.restype = BOOL
kernel32.CloseHandle.argtypes = [
    HANDLE # [in] hObject
]
# https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-gethandleinformation
kernel32.GetHandleInformation.restype = BOOL
kernel32.GetHandleInformation.argtypes = [
    HANDLE, # [in] hObject
    PDWORD, # [out] lpdwFlags
]
# https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess
kernel32.OpenProcess.restype = HANDLE
kernel32.OpenProcess.argtypes = [
    DWORD, # [in] dwDesiredAccess
    BOOL, # [in] bInheritHandle
    DWORD, # [in] dwProcessId
]
CloseHandle = kernel32.CloseHandle
GetCurrentProcess = kernel32.GetCurrentProcess
GetHandleInformation = kernel32.GetHandleInformation
GetProcessId = kernel32.GetProcessId
OpenProcess = kernel32.OpenProcess

advapi32 = ctypes.WinDLL("advapi32")

# https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-adjusttokenprivileges
advapi32.AdjustTokenPrivileges.restype = BOOL
advapi32.AdjustTokenPrivileges.argtypes = [
    HANDLE, # [in] TokenHandle
    BOOL, # [in] DisableAllPrivileges
    POINTER(TOKEN_PRIVILEGES), # [in, optional] NewState
    DWORD, # [in] BufferLength
    POINTER(TOKEN_PRIVILEGES), # [out, optional] PreviousState
    PDWORD, # [out, optional] ReturnLength
]

# https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-lookupprivilegevaluew
advapi32.LookupPrivilegeValueW.restype = BOOL
advapi32.LookupPrivilegeValueW.argtypes = [
    LPCWSTR, # [in, optional] lpSystemName
    LPCWSTR, # [in] lpName
    POINTER(LUID) # [out] lpLuid
]
# https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocesstoken
advapi32.OpenProcessToken.restype = BOOL
advapi32.OpenProcessToken.argtypes = [
    HANDLE, # [in] ProcessHandle,
    DWORD, # [in] DesiredAccess
    PHANDLE, # [out] TokenHandle
]
AdjustTokenPrivileges = advapi32.AdjustTokenPrivileges
GetTokenInformation = advapi32.GetTokenInformation
LookupPrivilegeValueW = advapi32.LookupPrivilegeValueW
OpenProcessToken = advapi32.OpenProcessToken

# Ref: https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess
ntdll = ctypes.WinDLL("ntdll")
ntdll.NtQueryInformationProcess.restype = LONG
ntdll.NtQueryInformationProcess.argtypes = [
    HANDLE, # [in] ProcessHandle
    DWORD, # [in] ProcessInformationClass (actually an enum)
    c_void_p, # [out] ProcessInformation
    c_ulong, # [in] ProcessInformationLength
    PULONG, # [out, optional] ReturnLength
]
NtQueryInformationProcess = ntdll.NtQueryInformationProcess


def get_inherit_handles_for(proc_handle: HANDLE) -> set[HANDLE]:
    desired_size = c_ulong(0)
    actual_size = c_ulong(0)
    buffer = (ctypes.c_byte * 16)()
    # Query the first time to discover how large the return buffer needs to be
    ret = NtQueryInformationProcess(
        proc_handle,
        ProcessHandleInformation,
        ctypes.byref(buffer),
        16,
        ctypes.byref(desired_size)
    )

    print(desired_size.value)

    snapshot = PROCESS_HANDLE_SNAPSHOT_INFORMATION.allocate_bytes(desired_size.value)
    # Query to get the actual data
    ret = NtQueryInformationProcess(
        proc_handle,
        ProcessHandleInformation,
        ctypes.byref(snapshot),
        desired_size.value,
        ctypes.byref(actual_size)
    )

    print(actual_size.value)

    if ret == 0:
        handles = set[HANDLE]()
        handles_arr = snapshot.handles_array()
        for h in handles_arr:
            if not h.HandleValue:
                continue
            if h.HandleAttributes & OBJ_INHERIT:
                handles.add(h.HandleValue)
                # print("Inherit bit set:", hex(h.HandleValue), hex(h.HandleAttributes))
        return handles
    else:
        raise ctypes.WinError()

def main() -> None:
    ph = GetCurrentProcess()
    actual_size = c_ulong(0)

    basic_info = PROCESS_BASIC_INFORMATION()
    ctypes.memset(ctypes.byref(basic_info), 0, ctypes.sizeof(basic_info))
    NtQueryInformationProcess(
        ph,
        ProcessBasicInformation,
        ctypes.byref(basic_info),
        ctypes.sizeof(PROCESS_BASIC_INFORMATION),
        ctypes.byref(actual_size)
    )

    # print(hex(ph), int(basic_info.UniqueProcessId), int(basic_info.InheritedFromUniqueProcessId))

    # import sys
    # sys.stdout.flush()
    # import time
    # time.sleep(300)

    pph = OpenProcess(
        PROCESS_QUERY_INFORMATION,
        False,
        basic_info.InheritedFromUniqueProcessId
    )
    if pph == None:
        raise ctypes.WinError()

    self_inherited_handles = get_inherit_handles_for(ph)
    parent_inherited_handles = get_inherit_handles_for(pph)

    print("Self Handles")
    for h in self_inherited_handles:
        print(hex(h))

    print("Parent Handles")
    for h in parent_inherited_handles:
        print(hex(h))

    CloseHandle(ph)
    CloseHandle(pph)

    handles_inherited_from_parent = self_inherited_handles & parent_inherited_handles

    print("Inherited from parent:", len(handles_inherited_from_parent))
    for h in handles_inherited_from_parent:
        print(hex(h))
    

if __name__ == "__main__":
    main()

    # import time
    # time.sleep(600)