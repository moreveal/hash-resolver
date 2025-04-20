import json
from pathlib import Path
from hash_resolver.pattern import Pattern
from hash_resolver.utils import parse_hex_fields

def load_pattern(path: str | Path) -> Pattern:
    path = Path(path)
    with open(path, "r") as f:
        raw = json.load(f)
        raw["emu"] = parse_hex_fields(raw["emu"])
        return Pattern(raw)

def load_symbols(path: str | Path) -> list[str]:
    path = Path(path)
    with open(path, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]

def load_func_bytes(path: str | Path) -> bytes:
    path = Path(path)
    return path.read_bytes()
