from loguru import logger

from unicorn import *
from unicorn.x86_const import *

from hash_resolver.pattern import Pattern

from hash_resolver.execution.base import ExecutionContext
from hash_resolver.execution.runtime import RuntimeContext

from tqdm import tqdm

from typing import Optional

def get_hash_from_pattern(
	ctx: ExecutionContext,
	pattern: Pattern,
	func: bytes | int,
	arg_inputs: list[str]
) -> int:
	"""
	Execute the hasher function and return the resulting hash.

	:param ctx: Execution context (emulated or runtime)
	:param pattern: ABI pattern of the function
	:param func: Function bytes (emulation) or address (runtime)
	:param arg_inputs: List of argument values
	:return: Computed hash value as integer
	"""

	is_runtime = isinstance(ctx, RuntimeContext)

	mem_base = ctx.mem_base
	str_base = mem_base
	func_addr = mem_base + 0x1000 if not is_runtime else func  # real addr in runtime

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
			data = val.encode("utf-8") + b"\x00"
			addr = str_base + str_offset
			ctx.write(addr, data)
			arg_values.append(addr)
			str_offset += len(data)
		elif arg_def["type"].startswith("uint"):
			arg_values.append(int(val, 0) if isinstance(val, str) else int(val))
		else:
			raise NotImplementedError(f"Type {arg_def['type']} not supported yet")
 
	if isinstance(func, bytes):
		ctx.write(func_addr, func)
	elif isinstance(func, int):
		func_addr = func
	else:
		raise TypeError("func must be bytes (emulated) or int (runtime)")

	# Prepare stack
	pattern.prepare_stack(ctx, arg_values)

	# Build and run stub
	try:
		with ctx.run_stub(pattern, func_addr, arg_values):
			result = pattern.get_return_value(ctx)
	except Exception as e:
		raise RuntimeError(e)
	return result

def resolve_hash(
	ctx: ExecutionContext,
	pattern: Pattern,
	func_bytes: bytes,
	target_hash: int,
	candidates: list[str],
	arguments: Optional[dict[str, str]] = None,
	max: int = 1
) -> list[str] | None:
	'''
	Attempts to resolve a hash value to the original string using the provided hasher.
 
	Args:
		ctx: Execution context (emulated or runtime)
		pattern: Function ABI pattern.
		func_bytes: Function body (emulated mode only)
		target_hash: Target hash to resolve.
		candidates: List of strings to try.
		arguments: Optional extra arguments (e.g., seed).
		max: Max number of matches to return.
  
	Returns:
		A list of matching candidates, or None if no match found.
 	'''
    
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
			hash_val = get_hash_from_pattern(ctx, pattern, func_bytes, arg_inputs)
		except Exception as e:
			logger.exception(f"Failed to compute hash for {candidate}")
			return None

		if hash_val == target_hash:
			results.append(candidate)
			if len(results) >= max:
				break

	return results if results else None

def bulk_generate_hashes(
	ctx: ExecutionContext,
	pattern: Pattern,
	func: bytes | int,
	symbols: list[str],
	arguments: Optional[dict[str, str]] = None,
	callback: Optional[callable] = None
) -> dict[str, str]:
	"""
	Generate hash→symbol map for all given symbols.

	:param ctx: Execution context (emulated or runtime)
	:param pattern: Parsed ABI pattern for the function
	:param func: Function bytes (emulated) or address (runtime)
	:param symbols: List of strings to hash
	:param arguments: Additional args like seed
	:param callback: Optional progress callback(symbol, hash)
	:return: Dict of {hash_hex: symbol}
	"""
	results = {}

	for sym in tqdm(symbols, desc="Resolving symbols", unit="sym"):
		arg_inputs = []

		for arg in pattern.args:
			name = arg["name"]

			if arguments and name in arguments:
				val = arguments[name]
			elif arg.get("resolve_input", False):
				val = sym
			elif "default" in arg:
				val = arg["default"]
			else:
				raise ValueError(f"Missing argument: {name}")

			arg_inputs.append(val)

		try:
			hash_val = get_hash_from_pattern(ctx, pattern, func, arg_inputs)
			results[f"0x{hash_val:08X}"] = sym
			if callback:
				callback(sym, hash_val)
		except Exception as e:
			logger.exception(f"[!] Failed for '{sym}': {e}")
			break

	return results
