#!/usr/bin/env -S nix shell github:smallworld-re/smallworld#venv --command python

import logging
import sys

import smallworld

if len(sys.argv) != 2:
    print("You need to provide a number as an argument")
    sys.exit(1)

try:
    int(sys.argv[1])
except ValueError:
    print("You need to provide a number as an argument")
    sys.exit(1)

# Set up logging
smallworld.logging.setup_logging(level=logging.INFO)

# Define the platform. We support many platforms, but this is going to use a 32-bit PowerPC with bigendian byte order.
platform = smallworld.platforms.Platform(
    smallworld.platforms.Architecture.POWERPC32, smallworld.platforms.Byteorder.BIG
)

# Create a machine to hold all of our state
machine = smallworld.state.Machine()

# Create a CPU for our platform and add it to the machine
cpu = smallworld.state.cpus.CPU.for_platform(platform)
machine.add(cpu)

# Load and add code into the machine. These are just some raw bytes, but you can load from a file too. We also support loading from ELF and PE files. This code is a compares r3 against 100 and sets it to 1 if it's 100 and 0 otherwise.
raw_bytes = b"\x2c\x03\x00\x64\x40\x82\x00\x0c\x38\x60\x00\x01\x48\x00\x00\x08\x38\x60\x00\x00\x60\x00\x00\x00"
code = smallworld.state.memory.code.Executable.from_bytes(raw_bytes, address=0x1000)
machine.add(code)

# Set the instruction pointer to the code entrypoint
cpu.pc.set(code.address)

# Initialize argument registers
cpu.r3.set(int(sys.argv[1]))

# Create a PANDA-ng emulator. We also support Ghidra, Unicorn, and angr. Not all emulators support all platforms. They all share the same API.
panda_ng = smallworld.emulators.PandaEmulator(platform)

# Tell the emulator when to stop
panda_ng.add_exit_point(cpu.pc.get() + code.get_capacity())

# Emulate our machine
panda_machine = machine.emulate(panda_ng)

# # read out r3
panda_r3 = panda_machine.get_cpu().r3.get()

print(panda_r3)
