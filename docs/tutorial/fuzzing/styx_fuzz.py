"""Standalone SmallWorld + AFL++ fuzz harness (Styx backend, armel target).

Two pieces differ from ``unicorn_fuzz.py``:

1. The emulator class is ``StyxEmulator`` instead of ``UnicornEmulator``.
2. Styx's CycloneV target pre-maps the full 4 GiB address space (it emulates
   a SoC whose physical DDR3 backs every address), so the binary's intended
   "crash" — a write to ``0x12345678`` — succeeds silently rather than
   faulting. To still surface the bug to AFL we install a memory-write hook
   over the out-of-bounds range and pass a ``crash_callback`` that turns
   those writes into reported crashes. Real firmware harnesses face the
   same constraint: faults from a flat memory map are rare, so bug
   detection has to be modelled explicitly.

Run from this directory under AFL++::

    afl-fuzz -t 10000 -U -m none -i inputs -o outputs -- python3 styx_fuzz.py @@

The ``styxafl`` bridge also runs a single iteration of ``input_callback``
against the file you give it when ``__AFL_SHM_ID`` is unset, so this script
doubles as a smoke test outside AFL.
"""

from __future__ import annotations

import logging
import sys

import smallworld

smallworld.logging.setup_logging(level=logging.INFO)

# armel = 32-bit ARM, little-endian, V5T baseline.
platform = smallworld.platforms.Platform(
    smallworld.platforms.Architecture.ARM_V5T,
    smallworld.platforms.Byteorder.LITTLE,
)

machine = smallworld.state.Machine()
cpu = smallworld.state.cpus.CPU.for_platform(platform)

# Load the raw fuzz target at 0x1000.
code = smallworld.state.memory.code.Executable.from_filepath(
    "fuzz.armel.bin", address=0x1000
)

# Heap holds the 4-byte size field followed by the input buffer that vuln() reads.
HEAP_BASE = 0x2000
HEAP_SIZE = 0x4000
heap = smallworld.state.memory.heap.BumpAllocator(HEAP_BASE, HEAP_SIZE)

seed = b"goodgoodgood"
size_addr = heap.allocate_integer(
    len(seed), 4, "user input size", smallworld.platforms.Byteorder.LITTLE
)
heap.allocate_bytes(seed, "user input")

# vuln() lives at 0x1000; r0 holds the buffer pointer.
cpu.pc.set_content(0x1000)
cpu.r0.set_content(size_addr)

machine.add(heap)
machine.add(cpu)
machine.add(code)


emulator = smallworld.emulators.StyxEmulator(platform)
# 0x1000 + 92 = nop at the end of vuln(); normal exit.
emulator.add_exit_point(0x1000 + 92)

# Out-of-bounds-write detection. The heap lives at 0x2000–0x6000 and the
# code at 0x1000–0x105c; anything above 0x10000 is "the program just wrote
# to a wild pointer". A single-element list stands in for a nonlocal mutable
# flag the input/crash callbacks below share.
bug_triggered = [False]


def detect_oob_write(_emulator, _address, _size, _content):
    bug_triggered[0] = True


emulator.hook_memory_write(0x10000, 0xFFFFFFFF, detect_oob_write)


def input_callback(emulator, input_bytes, persistent_round, data):
    # AFL++ contract: return False to skip this input, None to continue.
    # ``emulator`` is the SmallWorld emulator instance — the same callback
    # works against the Unicorn backend (see ``unicorn_fuzz.py``).
    bug_triggered[0] = False  # Fresh slate for this iteration.
    if len(input_bytes) > 0x1000:
        return False
    emulator.write_memory_content(size_addr, bytes(input_bytes))
    return None


def validate_crash(_report):
    # The styxafl bridge invokes this once per iteration (because we pass
    # always_validate=True). Returning True tells AFL to record the run as
    # a crash; we say "yes" exactly when our OOB-write hook fired.
    return bug_triggered[0]


# AFL++ replaces argv[1] with each generated input file via @@.
input_file = sys.argv[1] if len(sys.argv) > 1 else "inputs/good_input"
machine.fuzz_with_file(
    emulator,
    input_callback,
    input_file,
    crash_callback=validate_crash,
    always_validate=True,
)
