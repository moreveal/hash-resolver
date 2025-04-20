import argparse
import pefile

def extract_exports(dll_path: str) -> list[str]:
    pe = pefile.PE(dll_path)
    exports = []

    if not hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        return []

    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        if exp.name:
            exports.append(exp.name.decode('utf-8'))

    return exports

def main():
    parser = argparse.ArgumentParser(description="Extract exported symbols from DLL")
    parser.add_argument("dll", help="Path to DLL file")
    parser.add_argument("-o", "--output", help="Output symbol list file", required=True)
    args = parser.parse_args()

    names = extract_exports(args.dll)

    with open(args.output, "w", encoding="utf-8") as f:
        for name in names:
            f.write(name + "\n")

    print(f"[+] Extracted {len(names)} symbols to {args.output}")

if __name__ == "__main__":
    main()
