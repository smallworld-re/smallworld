"""Standalone SmallWorld + AFL++ fuzz harness (Styx backend, armel target).

The only differences from ``unicorn_fuzz.py`` are the three highlighted lines:
the emulator class, the memory-write call inside the callback, and the fuzz
entry point on ``Machine``. Everything else is byte-for-byte identical.

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


def input_callback(processor, input_bytes, persistent_round, data):
    # AFL++ contract: return False to skip this input, None to continue.
    if len(input_bytes) > 0x1000:
        return False
    # ``processor`` is a styx_emulator.Processor; write_data is the Styx
    # analogue of Unicorn's uc.mem_write.
    processor.write_data(size_addr, bytes(input_bytes))
    return None


emulator = smallworld.emulators.StyxEmulator(platform)
# 0x1000 + 92 = nop at the end of vuln(); normal exit.
emulator.add_exit_point(0x1000 + 92)

# AFL++ replaces argv[1] with each generated input file via @@.
input_file = sys.argv[1] if len(sys.argv) > 1 else "inputs/good_input"
machine.fuzz_with_styx(emulator, input_callback, input_file)
