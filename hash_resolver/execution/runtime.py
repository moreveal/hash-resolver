import ctypes
import struct
from ctypes import wintypes
from hash_resolver.execution.base import ExecutionContext

kernel32 = ctypes.windll.kernel32

PAGE_EXECUTE_READWRITE = 0x40
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_RELEASE = 0x8000
CONTEXT_FULL = 0x00010007
CONTEXT_ALL = 0x00100000 | CONTEXT_FULL

IS_64 = ctypes.sizeof(ctypes.c_void_p) == 8

class RemoteThreadHandle:
	def __init__(self, hThread, ctx):
		self.hThread = hThread
		self.ctx = ctx
		self._exit_code = None
		self._alive = True

	def __enter__(self):
		if self._alive:
			kernel32.ResumeThread(self.hThread)
		return self

	def __exit__(self, exc_type, exc_val, exc_tb):
		if self._alive:
			kernel32.TerminateThread(self.hThread, 0)
			kernel32.CloseHandle(self.hThread)
			self._alive = False
			self.hThread = None

	def get_exit_code(self):
		if self._exit_code is not None:
			return self._exit_code
		raise RuntimeError("Thread hasn't exited yet")

	def get_reg(self, name: str) -> int:
		exit_code = wintypes.DWORD()
		if not kernel32.GetExitCodeThread(self.hThread, ctypes.byref(exit_code)):
			raise RuntimeError("GetExitCodeThread failed")
		if exit_code.value != 0x103:  # STILL_ACTIVE
			raise RuntimeError("Thread has exited")

		context = CONTEXT64() if self.ctx.arch == "x64" else CONTEXT32()
		context.ContextFlags = CONTEXT_ALL
		if not kernel32.GetThreadContext(self.hThread, ctypes.byref(context)):
			raise RuntimeError("GetThreadContext failed")

		name = name.lower()
		if self.ctx.arch == "x64":
			return {
				"rax": context.Rax, "rcx": context.Rcx, "rdx": context.Rdx, "rbx": context.Rbx,
				"rsp": context.Rsp, "rbp": context.Rbp, "rsi": context.Rsi, "rdi": context.Rdi,
				"r8": context.R8, "r9": context.R9, "r10": context.R10, "r11": context.R11,
				"r12": context.R12, "r13": context.R13, "r14": context.R14, "r15": context.R15,
				"rip": context.Rip
			}.get(name)
		else:
			return {
				"eax": context.Eax, "ecx": context.Ecx, "edx": context.Edx, "ebx": context.Ebx,
				"esp": context.Esp, "ebp": context.Ebp, "esi": context.Esi, "edi": context.Edi,
				"eip": context.Eip,
			}.get(name)


class CONTEXT64(ctypes.Structure):
	_fields_ = [
		("P1Home", ctypes.c_ulonglong),
		("P2Home", ctypes.c_ulonglong),
		("P3Home", ctypes.c_ulonglong),
		("P4Home", ctypes.c_ulonglong),
		("P5Home", ctypes.c_ulonglong),
		("P6Home", ctypes.c_ulonglong),
		("ContextFlags", ctypes.c_ulong),
		("MxCsr", ctypes.c_ulong),
		("SegCs", ctypes.c_ushort),
		("SegDs", ctypes.c_ushort),
		("SegEs", ctypes.c_ushort),
		("SegFs", ctypes.c_ushort),
		("SegGs", ctypes.c_ushort),
		("SegSs", ctypes.c_ushort),
		("EFlags", ctypes.c_ulong),
		("Dr0", ctypes.c_ulonglong),
		("Dr1", ctypes.c_ulonglong),
		("Dr2", ctypes.c_ulonglong),
		("Dr3", ctypes.c_ulonglong),
		("Dr6", ctypes.c_ulonglong),
		("Dr7", ctypes.c_ulonglong),
		("Rax", ctypes.c_ulonglong),
		("Rcx", ctypes.c_ulonglong),
		("Rdx", ctypes.c_ulonglong),
		("Rbx", ctypes.c_ulonglong),
		("Rsp", ctypes.c_ulonglong),
		("Rbp", ctypes.c_ulonglong),
		("Rsi", ctypes.c_ulonglong),
		("Rdi", ctypes.c_ulonglong),
		("R8", ctypes.c_ulonglong),
		("R9", ctypes.c_ulonglong),
		("R10", ctypes.c_ulonglong),
		("R11", ctypes.c_ulonglong),
		("R12", ctypes.c_ulonglong),
		("R13", ctypes.c_ulonglong),
		("R14", ctypes.c_ulonglong),
		("R15", ctypes.c_ulonglong),
		("Rip", ctypes.c_ulonglong),
	]


class CONTEXT32(ctypes.Structure):
	_fields_ = [
		("ContextFlags", ctypes.c_ulong),
		("Dr0", ctypes.c_ulong),
		("Dr1", ctypes.c_ulong),
		("Dr2", ctypes.c_ulong),
		("Dr3", ctypes.c_ulong),
		("Dr6", ctypes.c_ulong),
		("Dr7", ctypes.c_ulong),
		("FloatSave", ctypes.c_byte * 112),
		("SegGs", ctypes.c_ulong),
		("SegFs", ctypes.c_ulong),
		("SegEs", ctypes.c_ulong),
		("SegDs", ctypes.c_ulong),
		("Edi", ctypes.c_ulong),
		("Esi", ctypes.c_ulong),
		("Ebx", ctypes.c_ulong),
		("Edx", ctypes.c_ulong),
		("Ecx", ctypes.c_ulong),
		("Eax", ctypes.c_ulong),
		("Ebp", ctypes.c_ulong),
		("Eip", ctypes.c_ulong),
		("SegCs", ctypes.c_ulong),
		("EFlags", ctypes.c_ulong),
		("Esp", ctypes.c_ulong),
		("SegSs", ctypes.c_ulong),
	]


class RuntimeContext(ExecutionContext):
	def __init__(self, hProcess: int, arch: str):
		self.hProcess = hProcess
		self.arch = arch
		self.allocs = []

		self._last_thread = None

		kernel32.WriteProcessMemory.argtypes = [
			wintypes.HANDLE,      # hProcess
			wintypes.LPVOID,      # lpBaseAddress
			wintypes.LPCVOID,     # lpBuffer
			ctypes.c_size_t,      # nSize
			ctypes.POINTER(ctypes.c_size_t)  # lpNumberOfBytesWritten
		]
		kernel32.WriteProcessMemory.restype = wintypes.BOOL
		
		kernel32.VirtualAllocEx.restype = ctypes.c_void_p
		kernel32.VirtualAllocEx.argtypes = [
			wintypes.HANDLE,
			wintypes.LPVOID,
			ctypes.c_size_t,
			wintypes.DWORD,
			wintypes.DWORD
		]
  
		kernel32.CreateRemoteThread.restype = ctypes.c_void_p
		kernel32.CreateRemoteThread.argtypes = [
			ctypes.c_void_p,  # hProcess
			ctypes.c_void_p,  # lpThreadAttributes
			ctypes.c_size_t,  # dwStackSize
			ctypes.c_void_p,  # lpStartAddress
			ctypes.c_void_p,  # lpParameter
			ctypes.c_ulong,   # dwCreationFlags
			ctypes.POINTER(ctypes.c_ulong)  # lpThreadId
		]

		self._last_rsp = None
		self._last_exit_code = None
		self._stub_hang_addr = None
  
		self._init_memory()
  
	def _init_memory(self):
		self.mem_size = 2 * 1024 * 1024
		self.mem_base = self.alloc(self.mem_size)
  
	def write(self, addr: int, data: bytes):
		n = ctypes.c_size_t()
		lpBaseAddress = ctypes.c_void_p(addr)
		buf = ctypes.create_string_buffer(data, len(data))
		res = kernel32.WriteProcessMemory(
			self.hProcess,
			lpBaseAddress,
			ctypes.byref(buf),
			len(data),
			ctypes.byref(n)
		)
		if not res:
			raise RuntimeError("WriteProcessMemory failed")

	def read(self, addr: int, size: int) -> bytes:
		buf = ctypes.create_string_buffer(size)
		n = ctypes.c_size_t()
		if not kernel32.ReadProcessMemory(self.hProcess, ctypes.c_void_p(addr), buf, size, ctypes.byref(n)):
			raise RuntimeError("ReadProcessMemory failed")
		return buf.raw

	def alloc(self, size: int) -> int:
		addr = kernel32.VirtualAllocEx(self.hProcess, 0, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
		if not addr:
			raise RuntimeError("VirtualAllocEx failed")
		self.allocs.append(addr)
		return addr

	def cleanup(self):
		for addr in self.allocs:
			kernel32.VirtualFreeEx(self.hProcess, ctypes.c_void_p(addr), 0, MEM_RELEASE)
		self.allocs.clear()

	def reg_read(self, name: str):
		return self._active_thread.get_reg(name)

	def reg_write(self, name: str, value: int):
		raise NotImplementedError("Register writing not supported yet")

	def build_call_stub(self, pattern, func_addr: int, arg_values: list[int]) -> tuple[int, int]:
		if pattern.arch == "x86":
			return self._build_stub_x86(pattern, func_addr, arg_values)
		elif pattern.arch == "x64":
			return self._build_stub_x64(pattern, func_addr, arg_values)
		else:
			raise NotImplementedError("Unsupported arch")

	def _build_stub_x86(self, pattern, func_addr, args):
		sc = b""

		if pattern.calling_convention in ["cdecl", "stdcall"]:
			for arg in reversed(args):
				sc += b"\x68" + struct.pack("<I", arg)
		elif pattern.calling_convention == "fastcall":
			if len(args) > 0:
				sc += b"\xB9" + struct.pack("<I", args[0])  # mov ecx, arg0
			if len(args) > 1:
				sc += b"\xBA" + struct.pack("<I", args[1])  # mov edx, arg1
			for arg in reversed(args[2:]):
				sc += b"\x68" + struct.pack("<I", arg)

		sc += b"\xB8" + struct.pack("<I", func_addr)  # mov eax, func
		sc += b"\xFF\xD0"                             # call eax

		stub_addr = self.mem_base + 0x2000
		self._stub_hang_addr = stub_addr + len(sc)
		sc += b"\xEB\xFE"  # jmp $
   
		self.write(stub_addr, sc)
		return stub_addr, stub_addr + len(sc)

	def _build_stub_x64(self, pattern, func_addr, args):
		sc = b""

		mov_reg = [b"\x48\xb9", b"\x48\xba", b"\x49\xb8", b"\x49\xb9"]  # rcx, rdx, r8, r9
		for i, arg in enumerate(args[:4]):
			sc += mov_reg[i] + struct.pack("<Q", arg)

		sc += b"\x48\x83\xec\x28"  # sub rsp, 0x28 (shadow space + align)

		for arg in reversed(args[4:]):
			sc += b"\x68" + struct.pack("<I", arg & 0xFFFFFFFF)

		sc += b"\x48\xb8" + struct.pack("<Q", func_addr)  # mov rax, func
		sc += b"\xff\xd0"                                 # call rax
		sc += b"\x48\x83\xc4\x28"                         # add rsp, 0x28
  
		stub_addr = self.mem_base + 0x2000
		self._stub_hang_addr = stub_addr + len(sc)
		sc += b"\xEB\xFE"  # jmp $
		
		self.write(stub_addr, sc)
		return stub_addr, stub_addr + len(sc)

	def run_stub(self, pattern, func_addr: int, args: list[int], auto_wait=True):
		stub_start, _ = self.build_call_stub(pattern, func_addr, args)
		thread_id = wintypes.DWORD()
  
		pattern._last_arg_values = args

		hThread = kernel32.CreateRemoteThread(
			self.hProcess, None, 0,
			ctypes.c_void_p(stub_start),
			None,
			0x00000004,  # CREATE_SUSPENDED
			ctypes.byref(thread_id)
		)
		if not hThread:
			raise RuntimeError("CreateRemoteThread failed")

		if auto_wait:
			kernel32.ResumeThread(hThread)
			self._active_thread = RemoteThreadHandle(hThread, self)
   
			import time
			t_start = time.time()
			while (time.time() - t_start) < 5.0:  # timeout 5s
				try:
					rip = self.reg_read("rip")
					if rip == self._stub_hang_addr:
						break
				except Exception:
					pass
				time.sleep(0.01)
			else:
				raise TimeoutError(f"RIP did not reach hang at 0x{self._stub_hang_addr:X}, make sure the call is correct (RIP: 0x{rip:X})")
		else:
			self._active_thread = RemoteThreadHandle(hThread, self)
  
		return self._active_thread

	def __del__(self):
		self.cleanup()
