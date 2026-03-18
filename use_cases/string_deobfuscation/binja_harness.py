"""
This harness runs functions in fake malware `strdeobfus` to decrypt
the data section and creates a new binary `strdeobfus2` with the
decrypted data section.

This version loads from a Binary Ninja database (.bndb) so that
platform, base address, sections, symbols, and executable bounds are
all derived automatically from the analysed database.

Usage:
    python deobf_strs_bndb.py strdeobfus.bndb [strdeobfus]

    arg 1 – path to the .bndb file (required)

"""

import logging
import sys

import smallworld

# ── CLI args ──────────────────────────────────────────────────────────

if len(sys.argv) < 2:
    print(f"Usage: {sys.argv[0]} <path.bndb>")
    sys.exit(1)

bndb_path = sys.argv[1]

# ── Logging ───────────────────────────────────────────────────────────

smallworld.logging.setup_logging(level=logging.INFO)

# ── Load the Binary Ninja database ────────────────────────────────────
# BinjaDatabase reads platform, base address, sections, executable
# bounds, and symbols directly from the .bndb file.

code = smallworld.state.memory.code.Executable.from_bndb(bndb_path)

# The platform is auto-detected from the database.
platform = code.platform
print(f"Detected platform: {platform}")
print(f"Image base: {hex(code.address)}")
print(f"Entry point: {hex(code.entry_point)}")

# ── Function addresses ────────────────────────────────────────────────
# Look up the target functions by symbol name from the database.
# Fall back to hardcoded addresses if the symbols aren't found.


def find_symbol_addr(code, name, fallback=None):
    """Return the address of the first symbol matching *name*."""
    for sym in code._symbols:
        if sym["name"] == name:
            return sym["address"]
    if fallback is not None:
        print(f"Warning: symbol {name!r} not found, using fallback {hex(fallback)}")
        return fallback
    raise RuntimeError(f"Symbol {name!r} not found in database")


kringle_things_start = find_symbol_addr(code, "kringle_things", fallback=0x11FE)
kringle_things_end = find_symbol_addr(code, "main", fallback=0x1226)  # first addr after
kringle_thing_start = find_symbol_addr(code, "kringle_thing", fallback=0x11A9)
kringle_thing_end = (
    kringle_things_start  # kringle_thing ends where kringle_things begins
)

# Executable bounds come from the bndb's segment flags automatically,
# but if you need to restrict to specific functions you can override:
code.bounds.clear()
code.bounds.add_range((0x801753EC, 0x80175464))

exit_point = 0x80175464

# ── CPU ───────────────────────────────────────────────────────────────

cpu = smallworld.state.cpus.CPU.for_platform(platform)

# ── Stack ─────────────────────────────────────────────────────────────

stack = smallworld.state.memory.stack.Stack.for_platform(
    platform, code.address + code.size + 0x1000, 0x5000
)

cpu.rsp.set(stack.get_pointer() - 128)

# ── Entry point for emulation ─────────────────────────────────────────

cpu.rip.set(kringle_things_start)

# ── Build machine & emulate ───────────────────────────────────────────

machine = smallworld.state.Machine()
machine.add(cpu)
machine.add(code)
machine.add(stack)
machine.add_exit_point(exit_point)

emu = smallworld.emulators.UnicornEmulator(platform)
new_machine = machine.emulate(emu)
