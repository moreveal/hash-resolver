# 📘 Signature Format Specification

Each `signature.json` describes the rules for calling and emulating a particular hash-function.

It's used by framework for:

- correct prepare of arguments
- ABI function call
- result extraction
- memory and stack management

---

## 🔁 General structure

```json
{
  "name": "cdecl_hash32",
  "arch": "x86",
  "calling_convention": "cdecl",
  "args": [...],
  "return": { ... },
  "emu": { ... }
}
```

---

## 🧱 Parameters

🔹 `name`: `string`
> Unique signature name. Used by UI/CLI/logs.
>
**Пример**: `cdecl_hash32`

---

🔹 `arch`: `x86` | `x64`
> Executable function architecture. Describes registers, word size, ABI.

---

🔹 `calling_convention`: `cdecl` | `stdcall` | `fastcall` | `win64`
> ABI describing how arguments are passed and who should clears the stack.

---

🔹 `args`: `Array<Object>`
> List of arguments that the function expects
>
Each argument:
```json
{
    "name": "input_str",
    "type": "char*",
    "default": "LoadLibraryA" // [optional]
    "resolve_input": true // [optional, but required at least 1]
}
```

- `name`: name for logging/debug
- `type`: text description of the type (`char*`, `uint32`, etc.)
- `default`: string or number (if you want to set the value in advance)
- `resolve_input`: is string for hashing?

---

🔹 `return`: `Object`
> Describes where to read the result from after invocation

```json
{
    "type": "uint32",
    "from": "reg:eax"
}
```
Possible values `from`:
- `reg:<name>` - read from register
Examples: `reg:eax`, `reg:rax`, `reg:edx`

- `mem:[<addr>]` - read from memory
Examples: `mem:[0x0040A010]` - absolute, `mem:[esp+4]` - ESP offset, `mem:[rsp+0x30]` - Win64 offset

- `deref:<arg_name>` - dereference the argument
Examples: `deref:out_ptr` - if argument `out_ptr = 0x00450000`, it reads from `mem[0x00450000]`

> Value type(`type`) are affects the size of the load:
- `uint32`, `int` → 4 bytes
- `uint64` → 8 bytes

---

🔹 `emu`: `Object`
> Execution environment parameters
```json
{
    "stack_base": "0x00FF0000",
    "stack_size": "0x10000",
    "mem_base": "0x00400000",
    "esp_offset": "0x8000"
}
```

|Field|Type|Description|
|-|-----------|---|
|`stack_base`|string|Base stack address (should be aligned)|
|`stack_size`|string|How many bytes to map for the stack|
|`mem_base`|string|Which should be writed string, function and the call stub|
|`esp_offset`|string|Offset from `stack_base` → it is start `ESP`/`RSP`

---

## 🧪 Example

```json
{
  "name": "cdecl_hash32",
  "arch": "x86",
  "calling_convention": "cdecl",
  "args": [
    {
      "name": "input_str",
      "type": "char*",
      "resolve_input": true
    }
  ],
  "return": {
    "type": "uint32",
    "from": "reg:eax"
  },
  "emu": {
    "stack_base": "0x00FF0000",
    "stack_size": "0x10000",
    "mem_base": "0x00400000",
    "esp_offset": "0x8000"
  }
}
```

---

## 📌 Features
- All hex values(`stack_base`, `mem_base`, etc.) must be strings(`"0x...`) - it parse automatically
- `default` values for arguments may be used for CLI-tests
- Extensions (`inlined`, `ret-void`, `multiple-ret`, `memory-result-ptr`) - will be added as needed

---

## 📁 Where to use it
You can pass your `signature.json` to the CLI shell for tests:
```bash
hashres resolve --pattern resources/signatures/cdecl_hash32.json ...
```
