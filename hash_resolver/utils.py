def parse_hex_fields(emu: dict) -> dict:
    out = {}
    for k, v in emu.items():
        if isinstance(v, str) and v.startswith("0x"):
            out[k] = int(v, 16)
        else:
            out[k] = v
    return out
