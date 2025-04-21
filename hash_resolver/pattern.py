import struct
from loguru import logger
from unicorn import *
from unicorn.x86_const import *

DEBUG_MODE = False

class Pattern:
    def __init__(self, pattern: dict):
        self.name = pattern["name"]
        self.arch = pattern["arch"]
        self.calling_convention = pattern["calling_convention"]
        self.args = pattern["args"]
        self.ret = pattern["return"]
        self.emu = pattern["emu"]

    def prepare_stack(self, mu, arg_values: list):
        self._last_arg_values = arg_values # save for deref later
        
        if DEBUG_MODE:
            logger.debug(f"[{self.name}] Preparing stack for arch={self.arch}, cc={self.calling_convention}, args={arg_values}")
        if self.arch == "x86":
            esp = self.emu["stack_base"] + self.emu["esp_offset"]

            if self.calling_convention in ["cdecl", "stdcall"]:
                esp -= 4
                mu.mem_write(esp, b"\x00\x00\x00\x00")  # fake ret

                for val in reversed(arg_values):
                    esp -= 4
                    mu.mem_write(esp, val.to_bytes(4, "little"))

                self._last_arg_values = arg_values
            elif self.calling_convention == "fastcall":
                if len(arg_values) > 0:
                    mu.reg_write(UC_X86_REG_ECX, arg_values[0])
                    if DEBUG_MODE:
                        logger.debug(f"[x86 fastcall] ecx = 0x{arg_values[0]:08X}")
                if len(arg_values) > 1:
                    mu.reg_write(UC_X86_REG_EDX, arg_values[1])
                    if DEBUG_MODE:
                        logger.debug(f"[x86 fastcall] edx = 0x{arg_values[1]:08X}")
                for val in reversed(arg_values[2:]):
                    esp -= 4
                    mu.mem_write(esp, val.to_bytes(4, "little"))
                    if DEBUG_MODE:
                        logger.debug(f"[x86 fastcall] push 0x{val:08X} -> esp=0x{esp:08X}")
            else:
                raise NotImplementedError(f"Unsupported calling convention: {self.calling_convention}")

            mu.reg_write(UC_X86_REG_ESP, esp)
            return esp

        elif self.arch == "x64":
            rsp = self.emu["stack_base"] + self.emu["esp_offset"]

            win64_regs = [UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9]
            for i, val in enumerate(arg_values[:4]):
                mu.reg_write(win64_regs[i], val)
                if DEBUG_MODE:
                    reg_name = ["rcx", "rdx", "r8", "r9"][i]
                    logger.debug(f"[x64] {reg_name} = 0x{val:016X}")

            for val in reversed(arg_values[4:]):
                rsp -= 8
                mu.mem_write(rsp, val.to_bytes(8, "little"))
                if DEBUG_MODE:
                    logger.debug(f"[x64] extra arg push 0x{val:016X} -> rsp=0x{rsp:016X}")

            rsp -= 0x20  # shadow space
            mu.reg_write(UC_X86_REG_RSP, rsp)
            if DEBUG_MODE:
                logger.debug(f"[x64] Final RSP after shadow space: 0x{rsp:016X}")
            return rsp

        else:
            raise NotImplementedError(f"Unsupported arch: {self.arch}")

    def get_return_value(self, mu):
        ret_from = self.ret["from"]
        if DEBUG_MODE:
            logger.debug(f"[{self.name}] Reading return value from: {ret_from}")

        reg_map = {
            "eax": UC_X86_REG_EAX, "ebx": UC_X86_REG_EBX, "ecx": UC_X86_REG_ECX,
            "edx": UC_X86_REG_EDX, "edi": UC_X86_REG_EDI, "esi": UC_X86_REG_ESI,
            "rax": UC_X86_REG_RAX, "rbx": UC_X86_REG_RBX, "rcx": UC_X86_REG_RCX,
            "rdx": UC_X86_REG_RDX, "rdi": UC_X86_REG_RDI, "rsi": UC_X86_REG_RSI
        }

        if ret_from.startswith("reg:"):
            reg = ret_from.split(":")[1].lower()
            val = mu.reg_read(reg_map[reg])
            if DEBUG_MODE:
                logger.debug(f"[return] {reg} = 0x{val:X}")
            return val

        elif ret_from.startswith("mem:["):
            addr_str = ret_from[5:-1]
            if addr_str.startswith("rsp+"):
                offset = int(addr_str[4:], 16)
                rsp = mu.reg_read(UC_X86_REG_RSP)
                addr = rsp + offset
            elif addr_str.startswith("esp+"):
                offset = int(addr_str[4:], 16)
                esp = mu.reg_read(UC_X86_REG_ESP)
                addr = esp + offset
            else:
                addr = int(addr_str, 16) if addr_str.startswith("0x") else int(addr_str)

            val = int.from_bytes(mu.mem_read(addr, 8 if self.arch == "x64" else 4), "little")
            if DEBUG_MODE:
                logger.debug(f"[return] mem[0x{addr:X}] = 0x{val:X}")
            return val
        
        elif ret_from.startswith("deref:"):
            arg_name = ret_from.split(":", 1)[1]
            arg_index = next(i for i, a in enumerate(self.args) if a["name"] == arg_name)
            addr = self._last_arg_values[arg_index]
            size = 8 if self.arch == "x64" else 4
            val = int.from_bytes(mu.mem_read(addr, size), "little")
            if DEBUG_MODE:
                logger.debug(f"[return] deref({arg_name}) @ 0x{addr:X} = 0x{val:X}")
            return val

        else:
            raise NotImplementedError(f"Unsupported return descriptor: {ret_from}")

    def build_call_stub(self, mu, stub_addr: int, func_addr: int) -> tuple[int, int]:
        if DEBUG_MODE:
            logger.debug(f"[{self.name}] Building call stub at 0x{stub_addr:X} -> func 0x{func_addr:X}")

        if self.arch == "x86":
            code = b"\xB8" + struct.pack("<I", func_addr) + b"\xFF\xD0"  # mov eax, func_addr; call eax
        elif self.arch == "x64":
            code = b"\x48\xB8" + struct.pack("<Q", func_addr) + b"\xFF\xD0"  # mov rax, func_addr; call rax
        else:
            raise NotImplementedError(f"Unsupported arch: {self.arch}")

        mu.mem_write(stub_addr, code)
        if DEBUG_MODE:
            logger.debug(f"[call stub] {code.hex()}")
        return stub_addr, stub_addr + len(code)
