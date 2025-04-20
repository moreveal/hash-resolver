# IDA Plugin for Hash Resolver

This is the IDA Pro integration for [`hash-resolver`](https://github.com/yourname/hash-resolver), a tool for emulating API hash functions via Unicorn engine.

## 🔧 Setup

1. **Install the project** in the same Python environment used by IDA:

```bash
pip install -e .
```

> ⚠ Make sure you are using the same Python version as IDA (check IDAPython log).
>

2. **Link the plugin into IDA's plugin directory:**
```bash
mklink /D "IDA\plugins\hashres" "script\path\ida_plugin"
```
> Replace the paths with yours.
You can also just copy the folder manually if symlinks don't work.
>

3. Manually create `hashres_plugin.py` (the stub) in the same `plugins/` folder:
```python
from hashres.plugin import PLUGIN_ENTRY as real_entry

def PLUGIN_ENTRY():
    return real_entry()
```

4. **Restart IDA.** The plugin should load automatically.

---

## ✅ Usage
- Right-click a hashing function (in disassembly or pseudocode)
- Select "Resolve hash for this function"
- Choose the signature, enter hash & symbols file
- Boom.

---

## 📁 Notes
- Signature JSONs are expected in ida_plugin/signatures/
- Symbol list = `.txt` file with one symbol name per line
- Emulator logic is fully shared with CLI version

---

## 🧠 Troubleshooting
- Plugin doesn't load? Check:
    - `Python version` matches IDA's (shown on startup)
    - `pip install -e .` installed in correct environment
    - `hash_resolver` is visible in `sys.path`
- Still stuck? Run the inside IDA:
    ```py
    import sys; print(sys.path)
    ```
