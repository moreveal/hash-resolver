from unicorn import *
from hash_resolver.execution.base import ExecutionContext, MAP_REGION
from hash_resolver.emulator import Emulator

from contextlib import nullcontext

class EmulatedContext(ExecutionContext):
    def __init__(self, emu: Emulator):
        self.mu = emu.get_mu()
        self.emu = emu
        self.arch = emu.arch
        self.mem_base = emu.mem_base
        self.mem_size = emu.mem_size
        
        self._alloc_offset = 0
        
    def write(self, addr, data):
        self.mu.mem_write(addr, data)
        
    def read(self, addr, size):
        return self.mu.mem_read(addr, size)

    def reg_read(self, name):
        return self.mu.reg_read(self._reg_map(name))

    def reg_write(self, name, value):
        self.mu.reg_write(self._reg_map(name), value)
        
    def build_call_stub(self, pattern, func_addr: int, arg_values: list[int] = None) -> tuple[int, int]:
        if pattern.arch == "x86":
            return self._build_stub_x86(pattern, func_addr)
        elif pattern.arch == "x64":
            return self._build_stub_x64(pattern, func_addr)
        else:
            raise NotImplementedError("Unsupported arch")
        
    def _build_stub_x86(self, pattern, func_addr: int, args = None) -> tuple[int, int]:
        code = b"\xB8" + func_addr.to_bytes(4, "little")  # mov eax, func
        code += b"\xFF\xD0"  # call eax
        stub_addr = self.get_map_region(MAP_REGION.STUB_BYTES)
        self.write(stub_addr, code)
        return stub_addr, stub_addr + len(code)
    
    def _build_stub_x64(self, pattern, func_addr: int, args = None) -> tuple[int, int]:
        code = b"\x48\x83\xEC\x28"  # sub rsp, 0x28 (shadow space)
        code += b"\x48\xB8" + func_addr.to_bytes(8, "little")  # mov rax, func
        code += b"\xFF\xD0"  # call rax
        code += b"\x48\x83\xC4\x28"  # add rsp, 0x28
        stub_addr = self.get_map_region(MAP_REGION.STUB_BYTES)
        self.write(stub_addr, code)
        return stub_addr, stub_addr + len(code)

    def start(self, start_addr, end_addr):
        self.mu.emu_start(start_addr, end_addr)

    def alloc(self, size: int) -> int:
        align = 8
        base = self.get_map_region(MAP_REGION.ALLOC)
        aligned_offset = (self._alloc_offset + (align - 1)) & ~(align - 1)
        addr = base + aligned_offset
        if addr + size > self.mem_base + self.mem_size:
            raise RuntimeError("Allocation failed")
        self._alloc_offset = aligned_offset + size
        
        return addr
    
    def cleanup(self):
        self._alloc_offset = 0
    
    def run_stub(self, pattern, func_addr: int, args: list[int]):
        start, end = self.build_call_stub(pattern, func_addr, args)
        self.start(start, end)
        return nullcontext()

    def _reg_map(self, name):
        from unicorn.x86_const import (
            UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX,
            UC_X86_REG_ESP, UC_X86_REG_RSP, UC_X86_REG_RAX, UC_X86_REG_RBX,
            UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9,
            UC_X86_REG_RDI, UC_X86_REG_RSI
        )
        name = name.lower()
        reg_dict = {
            "eax": UC_X86_REG_EAX, "ebx": UC_X86_REG_EBX, "ecx": UC_X86_REG_ECX, "edx": UC_X86_REG_EDX,
            "rax": UC_X86_REG_RAX, "rbx": UC_X86_REG_RBX, "rcx": UC_X86_REG_RCX, "rdx": UC_X86_REG_RDX,
            "r8": UC_X86_REG_R8, "r9": UC_X86_REG_R9, "esp": UC_X86_REG_ESP, "rsp": UC_X86_REG_RSP,
            "rdi": UC_X86_REG_RDI, "rsi": UC_X86_REG_RSI
        }
        return reg_dict[name]
