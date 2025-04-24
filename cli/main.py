import argparse
from pathlib import Path

from unicorn import *

from hash_resolver.emulator import Emulator
from hash_resolver.loader import load_pattern, load_func_bytes, load_symbols
from hash_resolver.core import get_hash_from_pattern, resolve_hash

from hash_resolver.execution.emulated import EmulatedContext
from hash_resolver.execution.runtime import RuntimeContext

import json
from hash_resolver.core import bulk_generate_hashes
from hash_resolver.execution.runtime_launcher import launch_runtime_process, kill_runtime_process

def cmd_bulk(args):
    pattern = load_pattern(Path(args.signature))
    symbols = load_symbols(args.symbols)
    overrides = parse_named_args(args.arg)

    if args.mode == "emu":
        func_bytes = load_func_bytes(args.funcbin)
        ctx = EmulatedContext(Emulator(pattern.arch, pattern.emu))
        results = bulk_generate_hashes(ctx, pattern, func_bytes, symbols, overrides)

    elif args.mode == "runtime":
        exe_path = args.exepath
        rva = int(args.func_rva, 0)
        
        process, func_addr = launch_runtime_process(exe_path, rva)
        ctx = RuntimeContext(process, pattern.arch)
        results = bulk_generate_hashes(ctx, pattern, func_addr, symbols, overrides)

        # Cleanup
        ctx.cleanup()
        kill_runtime_process(process)
    else:
        raise ValueError(f"Unsupported mode: {args.mode}")

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)


def parse_named_args(arg_list: list[str]) -> dict:
    result = {}
    for pair in arg_list:
        if "=" not in pair:
            raise ValueError(f"Invalid --arg format, expected name=value, got: {pair}")
        k, v = pair.split("=", 1)
        result[k.strip()] = v.strip()
    return result


def build_arg_inputs(pattern, overrides: dict, resolve_input_value: str | None = None):
    inputs = []
    for arg in pattern.args:
        name = arg["name"]
        if arg.get("resolve_input", False) and resolve_input_value is not None:
            inputs.append(resolve_input_value)
        elif name in overrides:
            inputs.append(overrides[name])
        elif "default" in arg:
            inputs.append(arg["default"])
        else:
            raise ValueError(f"Argument '{name}' is required but not provided")
    return inputs

def cmd_hash(args):
    pattern = load_pattern(Path(args.signature))
    func_bytes = load_func_bytes(args.funcbin)
    overrides = parse_named_args(args.arg)

    inputs = build_arg_inputs(pattern, overrides)
    
    ctx = EmulatedContext(Emulator(pattern.arch, pattern.emu))
    result = get_hash_from_pattern(ctx, pattern, func_bytes, inputs)
    print(f"[+] Hash: 0x{result:08X}")

def cmd_resolve(args):
    pattern = load_pattern(Path(args.signature))
    func_bytes = load_func_bytes(args.funcbin)
    symbols = load_symbols(args.symbols)
    overrides = parse_named_args(args.arg)

    ctx = EmulatedContext(Emulator(pattern.arch, pattern.emu))
    result = resolve_hash(ctx, pattern, func_bytes, args.hash, symbols, overrides)
    if result:
        print(f"[+] Match: {', '.join(result)}")
    else:
        print("[-] No match found.")

def main():
    parser = argparse.ArgumentParser(description="Hash Resolver CLI")
    subparsers = parser.add_subparsers(dest="mode", required=True)

    # hash mode
    hash_parser = subparsers.add_parser("hash", help="Calculate hash from string")
    hash_parser.add_argument("--signature", required=True)
    hash_parser.add_argument("--funcbin", required=True)
    hash_parser.add_argument("--arg", action="append", default=[], help="Function arg, format: name=value")
    hash_parser.set_defaults(func=cmd_hash)

    # resolve mode
    resolve_parser = subparsers.add_parser("resolve", help="Resolve hash to string")
    resolve_parser.add_argument("--signature", required=True)
    resolve_parser.add_argument("--funcbin", required=True)
    resolve_parser.add_argument("--hash", required=True, type=lambda x: int(x, 0))
    resolve_parser.add_argument("--symbols", required=True)
    resolve_parser.add_argument("--arg", action="append", default=[], help="Additional args for signature")
    resolve_parser.set_defaults(func=cmd_resolve)
    
    # bulk mode
    bulk_parser = subparsers.add_parser("bulk", help="Generate hash map for symbols list")
    bulk_parser.add_argument("--signature", required=True)
    bulk_parser.add_argument("--symbols", required=True)
    bulk_parser.add_argument("--arg", action="append", default=[])
    bulk_parser.add_argument("--mode", choices=["emu", "runtime"], required=True)
    bulk_parser.add_argument("--output", required=True)

    # for runtime mode only:
    bulk_parser.add_argument("--exepath", help="Target EXE (required for runtime)")
    bulk_parser.add_argument("--func-rva", help="Hasher RVA (required for runtime)")
    
    # for emulator mode only:
    bulk_parser.add_argument("--funcbin", help="Function bytes (required for emu)")

    bulk_parser.set_defaults(func=cmd_bulk)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
