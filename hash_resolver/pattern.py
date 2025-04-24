from loguru import logger
from hash_resolver.execution.base import ExecutionContext
from hash_resolver.execution.runtime import RuntimeContext

class Pattern:
    def __init__(self, pattern: dict, debug_mode = False):
        self.name = pattern["name"]
        self.arch = pattern["arch"]
        self.calling_convention = pattern["calling_convention"]
        self.args = pattern["args"]
        self.ret = pattern["return"]
        self.emu = pattern["emu"]
        self._last_arg_values = None
        self._pattern = pattern
        self.debug_mode = debug_mode

    def prepare_stack(self, ctx: ExecutionContext, arg_values: list):
        self._last_arg_values = arg_values
        if self.debug_mode:
            logger.debug(f"[{self.name}] Preparing stack for arch={self.arch}, cc={self.calling_convention}, args={arg_values}")
            
        if isinstance(ctx, RuntimeContext):
            return # do nothing for runtime (shellcode contains the arguments)

        if self.arch == "x86":
            esp = self.emu["stack_base"] + self.emu["esp_offset"]

            if self.calling_convention in ["cdecl", "stdcall"]:
                esp -= 4
                ctx.write(esp, b"\x00\x00\x00\x00")  # fake ret
                for val in reversed(arg_values):
                    esp -= 4
                    ctx.write(esp, val.to_bytes(4, "little"))

            elif self.calling_convention == "fastcall":
                if len(arg_values) > 0:
                    ctx.reg_write("ecx", arg_values[0])
                if len(arg_values) > 1:
                    ctx.reg_write("edx", arg_values[1])
                for val in reversed(arg_values[2:]):
                    esp -= 4
                    ctx.write(esp, val.to_bytes(4, "little"))

            ctx.reg_write("esp", esp)
            return esp

        elif self.arch == "x64":
            rsp = self.emu["stack_base"] + self.emu["esp_offset"]

            arg_regs = ["rcx", "rdx", "r8", "r9"]
            for i, val in enumerate(arg_values[:4]):
                ctx.reg_write(arg_regs[i], val)

            for val in reversed(arg_values[4:]):
                rsp -= 8
                ctx.write(rsp, val.to_bytes(8, "little"))

            rsp -= 0x20  # shadow space
            ctx.reg_write("rsp", rsp)
            return rsp

        else:
            raise NotImplementedError(f"Unsupported arch: {self.arch}")

    def get_return_value(self, ctx: ExecutionContext):
        ret_from = self.ret["from"]
        if self.debug_mode:
            logger.debug(f"[{self.name}] Reading return value from: {ret_from}")

        if ret_from.startswith("reg:"):
            reg = ret_from.split(":")[1].lower()
            val = ctx.reg_read(reg)
            if self.debug_mode:
                logger.debug(f"[return] {reg} = 0x{val:X}")
            return val

        elif ret_from.startswith("mem:["):
            addr_str = ret_from[5:-1]
            if addr_str.startswith("rsp+"):
                offset = int(addr_str[4:], 16)
                rsp = ctx.reg_read("rsp")
                addr = rsp + offset
            elif addr_str.startswith("esp+"):
                offset = int(addr_str[4:], 16)
                esp = ctx.reg_read("esp")
                addr = esp + offset
            else:
                addr = int(addr_str, 16)

            size = 8 if self.arch == "x64" else 4
            val = int.from_bytes(ctx.read(addr, size), "little")
            if self.debug_mode:
                logger.debug(f"[return] mem[0x{addr:X}] = 0x{val:X}")
            return val

        elif ret_from.startswith("deref:"):
            arg_name = ret_from.split(":", 1)[1]
            arg_index = next(i for i, a in enumerate(self.args) if a["name"] == arg_name)
            addr = self._last_arg_values[arg_index]
            size = 8 if self.arch == "x64" else 4
            val = int.from_bytes(ctx.read(addr, size), "little")
            if self.debug_mode:
                logger.debug(f"[return] deref({arg_name}) @ 0x{addr:X} = 0x{val:X}")
            return val

        else:
            raise NotImplementedError(f"Unsupported return descriptor: {ret_from}")
