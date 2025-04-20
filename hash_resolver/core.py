from loguru import logger

from unicorn import *
from unicorn.x86_const import *

from hash_resolver.pattern import Pattern
from hash_resolver.emulator import Emulator

from typing import Optional

def get_hash_from_pattern(pattern: Pattern, func_bytes: bytes, arg_inputs: list[str]) -> int:
    # Init emulator
    emu = Emulator(pattern.arch, pattern.emu)
    mu = emu.get_mu()

    # Memory layout:
    # str      -> mem_base + 0x0000
    # func     -> mem_base + 0x1000
    # stub     -> mem_base + 0x2000

    mem_base = pattern.emu["mem_base"]
    str_base = mem_base
    str_addr = mem_base
    func_addr = mem_base + 0x1000
    stub_addr = mem_base + 0x2000

    # Prepare arguments
    arg_values = []
    str_offset = 0
    for i, arg_def in enumerate(pattern.args):
        if i < len(arg_inputs):
            val = arg_inputs[i]
        elif "default" in arg_def:
            val = arg_def["default"]
        else:
            raise ValueError(f"Argument '{arg_def['name']}' is required but not provided")

        if arg_def["type"] == "char*":
            # Encode string and write to memory
            data = val.encode("utf-8") + b"\x00"
            addr = str_base + str_offset
            emu.write(addr, data)
            arg_values.append(addr)
            str_offset += len(data)
        elif arg_def["type"].startswith("uint"):
            arg_values.append(int(val, 0) if isinstance(val, str) else int(val))
        else:
            raise NotImplementedError(f"Type {arg_def['type']} not supported yet")

    # Function code
    emu.write(func_addr, func_bytes)

    # Prepare stack
    pattern.prepare_stack(mu, arg_values)

    # Build call stub
    call_start, call_end = pattern.build_call_stub(mu, stub_addr, func_addr)

    # Emulate
    try:
        emu.start(call_start, call_end)
    except UcError as e:
        logger.error(f"Unicorn crashed: {e}")
        if pattern.arch == "x86":
            logger.error(f"EIP: 0x{mu.reg_read(UC_X86_REG_EIP):08X}")
            logger.error(f"ESP: 0x{mu.reg_read(UC_X86_REG_ESP):08X}")
        else:
            logger.error(f"RIP: 0x{mu.reg_read(UC_X86_REG_RIP):016X}")
            logger.error(f"RSP: 0x{mu.reg_read(UC_X86_REG_RSP):016X}")
        raise

    # Return result
    return pattern.get_return_value(mu)

# --- old wrappers ---

cache = {}
def get_hash_cached(pattern: Pattern, func_bytes: bytes, args: list[str]) -> int:
    key = tuple(args)
    if key not in cache:
        cache[key] = get_hash_from_pattern(pattern, func_bytes, args)
    return cache[key]

def resolve_hash(
    pattern: Pattern,
    func_bytes: bytes,
    target_hash: int,
    candidates: list[str],
    arguments: Optional[dict[str, str]] = None,
    max: int = 1
) -> list[str] | None:
    results = []

    # Find the argument index with "resolve_input": true
    resolve_index = next(
        (i for i, arg in enumerate(pattern.args) if arg.get("resolve_input", False)),
        None
    )

    if resolve_index is None:
        raise ValueError("Pattern does not define any argument with resolve_input=true")

    for candidate in candidates:
        arg_inputs = []

        for i, arg in enumerate(pattern.args):
            name = arg["name"]

            if arguments and name in arguments:
                val = arguments[name]
            elif i == resolve_index:
                val = candidate
            elif "default" in arg:
                val = arg["default"]
            else:
                raise ValueError(f"Missing argument: {name}")

            arg_inputs.append(val)

        try:
            hash_val = get_hash_from_pattern(pattern, func_bytes, arg_inputs)
        except Exception as e:
            logger.warning(f"Failed to compute hash for {candidate}: {e}")
            continue

        if hash_val == target_hash:
            results.append(candidate)
            if len(results) >= max:
                break

    return results if results else None
