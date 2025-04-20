import subprocess
import tempfile
import json
import sys
from pathlib import Path

FNV1A_BYTES = b'\x55\x8b\xec\x83\xec\x08\xc7\x45\xfc\xc5\x9d\x1c\x81\x8b\x45\x08\x0f\xbe\x08\x85\xc9\x74\x27\x8b\x55\x08\x0f\xb6\x02\x89\x45\xf8\x8b\x4d\x08\x83\xc1\x01\x89\x4d\x08\x8b\x55\xfc\x33\x55\xf8\x89\x55\xfc\x69\x45\xfc\x93\x01\x00\x01\x89\x45\xfc\xeb\xcf\x8b\x45\xfc\x8b\xe5\x5d\xc3\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\x55\x8b\xec\x33'

FNV1A_SIG = {
    "name": "test_pattern",
    "arch": "x86",
    "calling_convention": "cdecl",
    "args": [
        {"name": "input_str", "type": "char*", "resolve_input": True}
    ],
    "return": {"type": "uint32", "from": "reg:eax"},
    "emu": {
        "stack_base": "0x00FF0000",
        "stack_size": "0x10000",
        "mem_base": "0x00400000",
        "esp_offset": "0x8000"
    }
}

def test_cli_resolve():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        sig_file = tmp / "sig.json"
        bin_file = tmp / "func.bin"
        sym_file = tmp / "syms.txt"

        sig_file.write_text(json.dumps(FNV1A_SIG))
        bin_file.write_bytes(FNV1A_BYTES)
        sym_file.write_text("LoadLibraryA\nGetProcAddress\nExitProcess\n")

        proc = subprocess.run([
            sys.executable, "cli/main.py", "resolve",
            "--signature", str(sig_file),
            "--funcbin", str(bin_file),
            "--hash", "0x53B2070F",
            "--symbols", str(sym_file),
        ], capture_output=True, text=True)

        assert proc.returncode == 0
        assert "[+] Match: LoadLibraryA" in proc.stdout
