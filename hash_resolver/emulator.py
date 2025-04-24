from unicorn import *
from unicorn.x86_const import *

from enum import Enum

ARCH_MAP = {
    "x86": (UC_ARCH_X86, UC_MODE_32),
    "x64": (UC_ARCH_X86, UC_MODE_64),
}

class Emulator:
    def __init__(self, arch: str, emu_config: dict, debug_mode: bool = False):
        if arch not in ARCH_MAP:
            raise ValueError(f"Unsupported arch: {arch}")
        
        self.arch = arch
        self.config = emu_config
        self.uc = Uc(*ARCH_MAP[arch])

        self.stack_base = emu_config["stack_base"]
        self.stack_size = emu_config["stack_size"]
        self.mem_base = emu_config["mem_base"]
        self.mem_size = 2 * 1024 * 1024
        self.esp_offset = emu_config["esp_offset"]
        self.debug_mode = debug_mode
        
        self._init_memory()

    def _init_memory(self):
        self.uc.mem_map(self.stack_base, self.stack_size)
        self.uc.mem_map(self.mem_base, self.mem_size)  # shared block for str/func/stub

        if self.arch == "x86":
            self.uc.reg_write(UC_X86_REG_ESP, self.stack_base + self.esp_offset)
        else:
            self.uc.reg_write(UC_X86_REG_RSP, self.stack_base + self.esp_offset)

        if self.debug_mode:
            print(f"[emu] stack: 0x{self.stack_base:08X} size={self.stack_size}")
            print(f"[emu] mem:   0x{self.mem_base:08X} size={self.mem_size}")

    def write(self, addr: int, data: bytes):
        self.uc.mem_write(addr, data)

    def read(self, addr: int, size: int) -> bytes:
        return self.uc.mem_read(addr, size)

    def set_reg(self, reg, value):
        self.uc.reg_write(reg, value)

    def get_reg(self, reg):
        return self.uc.reg_read(reg)

    def start(self, start_addr: int, end_addr: int):
        if self.debug_mode:
            print(f"[emu] start: 0x{start_addr:08X} → 0x{end_addr:08X}")
        self.uc.emu_start(start_addr, end_addr)

    def get_mu(self) -> Uc:
        return self.uc
