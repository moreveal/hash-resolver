import ctypes
import time
import tempfile
import pefile
import win32process

from pathlib import Path

PROCESS_ALL_ACCESS = (0x000F0000 | 0x00100000 | 0xFFF)
CREATE_SUSPENDED = 0x00000004
kernel32 = ctypes.windll.kernel32

def patch_exe_jmp_hang(original_path: str) -> tuple[str, int]:
    with open(original_path, "rb") as f:
        raw = bytearray(f.read())

    pe = pefile.PE(data=bytes(raw))
    ep_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    ep_offset = pe.get_offset_from_rva(ep_rva)

    raw[ep_offset:ep_offset + 2] = b'\xEB\xFE'  # jmp $

    temp_path = Path(tempfile.gettempdir()) / (Path(original_path).stem + ".patched.exe")
    with open(temp_path, "wb") as f:
        f.write(raw)

    return str(temp_path), ep_rva


def get_image_base_safe(hProcess, retries=50, delay=0.1) -> int:
    for _ in range(retries):
        try:
            modules = win32process.EnumProcessModules(hProcess)
            return modules[0]
        except Exception as e:
            if hasattr(e, 'winerror') and e.winerror == 299:
                time.sleep(delay)
            else:
                raise
    raise RuntimeError("Failed to get ImageBase after retries")


def create_suspended_process(path: str):
    si = win32process.STARTUPINFO()
    return win32process.CreateProcess(
        None,
        str(path),
        None, None,
        False,
        CREATE_SUSPENDED,
        None, None,
        si
    )

def launch_runtime_process(exe_path: str, rva: int) -> tuple:
    '''
    Launch process and prepare it. You need to use kill_runtime_process() after using.

	:param exe_path: Executable path
	:param rva: Relative address of the hasher-function (from base)
	:return: (process, func_addr)
    '''
    
    patched_path, ep_rva = patch_exe_jmp_hang(exe_path)
    hProcess, hThread, pid, tid = create_suspended_process(patched_path)
    
    win32process.ResumeThread(hThread)
    time.sleep(0.5)
    
    image_base = get_image_base_safe(hProcess)
    hProcess = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    assert hProcess, "OpenProcess(PROCESS_ALL_ACCESS) failed"
    
    time.sleep(1.0) # wait for oep entry
    
    return (hProcess, image_base + rva)

def kill_runtime_process(hProcess: int) -> None:
    kernel32.TerminateProcess(hProcess, 0)
    kernel32.CloseHandle(hProcess)
