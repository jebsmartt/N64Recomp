#!/usr/bin/env python3
"""
patch_elf.py - Prepares mariogolf64.elf for use with N64Recomp.

Usage:
    python3 patch_elf.py

Input:  ../mariogolf64/build/mariogolf64.elf
Output: mariogolf64_patched.elf

Patches applied:
1. entry_TEXT_START: NOTYPE -> FUNC (entrypoint detection)
2. All ABS FUNC symbols in .main/.entry address range -> correct section
   (libultra/NuSystem symbols must be section-bound for recompiler to find them)
3. jr v0 at 0x800A384C -> nop
   (prevents unresolvable jump table analysis in func_800A2F50)
4. Clears overlays.txt
   (.ADD30 is a pure data overlay with no executable functions)
"""

import shutil
import struct
import sys
from pathlib import Path
from elftools.elf.elffile import ELFFile

REPO = Path(__file__).parent
SRC  = REPO.parent / "mariogolf64/build/mariogolf64.elf"
DST  = REPO / "mariogolf64_patched.elf"
OVERLAYS_TXT = REPO / "overlays.txt"

if not SRC.exists():
    print(f"ERROR: Source ELF not found: {SRC}")
    print("Run 'make' in the mariogolf64 repo first.")
    sys.exit(1)

shutil.copy2(SRC, DST)
print(f"Copied {SRC.name} -> {DST.name}")

with open(DST, "r+b") as f:
    elf = ELFFile(f)
    symtab = elf.get_section_by_name(".symtab")

    sections = {}
    for i, s in enumerate(elf.iter_sections()):
        sections[s.name] = {
            "index": i,
            "start": s["sh_addr"],
            "end":   s["sh_addr"] + s["sh_size"],
            "off":   s["sh_offset"],
        }

    main  = sections[".main"]
    entry = sections[".entry"]

    print(f".entry index={entry['index']}  "
          f"0x{entry['start']:08X}-0x{entry['end']:08X}")
    print(f".main  index={main['index']}  "
          f"0x{main['start']:08X}-0x{main['end']:08X}")

    patched_syms = 0
    for i, sym in enumerate(symtab.iter_symbols()):
        val   = sym.entry.st_value
        shndx = sym.entry.st_shndx
        typ   = sym.entry.st_info.type
        off   = symtab["sh_offset"] + i * symtab["sh_entsize"]

        # 1. entry_TEXT_START: NOTYPE -> FUNC
        if sym.name == "entry_TEXT_START":
            f.seek(off + 12)
            old = f.read(1)[0]
            f.seek(off + 12)
            f.write(bytes([(old & 0xF0) | 0x01]))
            print(f"  entry_TEXT_START -> FUNC")
            patched_syms += 1
            continue

        # 2. ABS FUNC symbols -> correct section
        if shndx == "SHN_ABS" and typ == "STT_FUNC":
            if main["start"] <= val < main["end"]:
                f.seek(off + 14)
                f.write(struct.pack(">H", main["index"]))
                patched_syms += 1
            elif entry["start"] <= val < entry["end"]:
                f.seek(off + 14)
                f.write(struct.pack(">H", entry["index"]))
                patched_syms += 1

    print(f"  {patched_syms} symbols patched")

    # 3. Nop unresolvable jr instructions
    jr_patches = [
        (0x800A384C, 0x00400008, "jr v0 in func_800A2F50"),
    ]
    for vram, expected, desc in jr_patches:
        file_off = main["off"] + (vram - main["start"])
        f.seek(file_off)
        actual = struct.unpack(">I", f.read(4))[0]
        if actual == expected:
            f.seek(file_off)
            f.write(struct.pack(">I", 0x00000000))
            print(f"  Nop'd {desc} at 0x{vram:08X}")
        else:
            print(f"  WARNING: Expected 0x{expected:08X} at 0x{vram:08X}, "
                  f"got 0x{actual:08X} — skipping {desc}")

# 4. Clear overlays.txt (.ADD30 is data-only, no executable functions)
OVERLAYS_TXT.write_text("")
print(f"  Cleared {OVERLAYS_TXT.name}")

print(f"\nDone -> {DST.name}")
print(f"Next: cd build && ./N64Recomp ../mariogolf.toml")
