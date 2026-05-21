"""Standalone SmallWorld + AFL++ fuzz harness (Styx backend, armel target).

The only difference from ``unicorn_fuzz.py`` is the emulator class — the
callback and ``Machine.fuzz_with_file`` call are identical, because
SmallWorld unifies the AFL bridge under a single backend-agnostic interface.

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


def input_callback(emulator, input_bytes, persistent_round, data):
    # AFL++ contract: return False to skip this input, None to continue.
    # ``emulator`` is the SmallWorld emulator instance — the same callback
    # works against the Unicorn backend (see ``unicorn_fuzz.py``).
    if len(input_bytes) > 0x1000:
        return False
    emulator.write_memory_content(size_addr, bytes(input_bytes))
    return None


emulator = smallworld.emulators.StyxEmulator(platform)
# 0x1000 + 92 = nop at the end of vuln(); normal exit.
emulator.add_exit_point(0x1000 + 92)

# AFL++ replaces argv[1] with each generated input file via @@.
input_file = sys.argv[1] if len(sys.argv) > 1 else "inputs/good_input"
machine.fuzz_with_file(emulator, input_callback, input_file)
