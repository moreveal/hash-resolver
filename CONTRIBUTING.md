## 🧩 Contributing to hash-resolver

First off — thanks for considering contributing!
This tool is made for reverse engineers, by reverse engineers — every real-world case improves it for everyone.

---

## ✅ What You Can Help With
**1. Inline hash functions support**
> Not all binaries isolate hash functions in dedicated subroutines.
Some implement them inline — so right-click → "Resolve function" doesn't help.
>
**Idea:**
Allow selecting an arbitrary instruction range in IDA and treat that as the "function".
**Tasks:**
- Add support for selection-based analysis
- Adjust plugin to grab bytes from selection (not just `get_func`)
- Maybe UI toggle: `Use selection instead of full function`

---

**2. Better error handling / fallback**
> Some patterns crash during emulation — need better user feedback.

**Tasks:**
- Graceful fallback when emulation fails (e.g., show reg dump or mem snapshot)
- Optionally dump emulator trace on failure

---

**3. Cross-architecture testing**
>Right now mostly tested with x86 32-bit.
x64 seems fine, but more edge cases welcome.

**Tasks:**
- Add test patterns + binaries for x64 (fastcall, Windows ABI)
- Expand CLI tests with multi-arg, mem-out cases

---

**4. Signature DB / presets**
> Could be cool to ship "known" patterns (FNV-1a, CRC32, Jenkins, etc.)
Maybe even a community-driven list?
>

---

## 🛠️ Dev Environment
**1.** Clone repo:
```bash
git clone https://github.com/moreveal/hash-resolver.git
cd hash-resolver
```

**2.** Install in editable mode (with IDA's Python):
```bash
pip install -e .
```

**3.** Link plugin into IDA:
```bash
mklink /D "IDA/plugins/hashres" "hash-resolver/ida_plugin"
```

---

## 📦 Structure

|Path|Description|
|-|-|
|`cli/`|	CLI entrypoint, accepts args + runs logic|
|`hash_resolver/`|	Core logic: emulator, pattern, etc.|
|`ida_plugin/`|	UI + integration with IDA|
|`resources/`|	Binary examples|
|`tests/`|	Pytest-based tests|

---

## 🧪 Submitting PRs
- Keep PRs small & focused
- Include sample test (if logic-related)
- Respect existing style (black-compatible, `snake_case`)
- Feel free to open Draft PRs to start discussion

---

Sound good? Open an issue, fork the repo — or jump straight into code.
👀 Thanks for helping improve reverse engineering tooling.
