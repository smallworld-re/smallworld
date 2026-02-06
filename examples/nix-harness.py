#!/usr/bin/env -S nix develop github:smallworld-re/smallworld#pythonEnv -c python

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

# This will be the input to our function
input_arg = int(sys.argv[1])

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
cpu.r3.set(input_arg)

# We need to establish when we want to stop
machine.add_exit_point(cpu.pc.get() + code.get_capacity())


# We support PANDA-ng, Ghidra, Unicorn, and angr. Not all emulators support all platforms. They all share the same API.

# Create a PANDA-ng emulator. 
panda_ng = smallworld.emulators.PandaEmulator(platform)

# Emulate our machine
panda_machine = machine.emulate(panda_ng)

# # read out r3
panda_r3 = panda_machine.get_cpu().r3.get()

# check that our function behaves the way we expect
if (input_arg == 100) and (panda_r3 != 1):
    sys.exit(1)
elif (input_arg != 100) and (panda_r3 != 0):
    sys.exit(1)

# Create a Ghidra emulator. 
ghidra = smallworld.emulators.GhidraEmulator(platform)

# Emulate our machine
ghidra_machine = machine.emulate(ghidra)

# read out r3
ghidra_r3 = ghidra_machine.get_cpu().r3.get()

# check that our function behaves the way we expect
if (input_arg == 100) and (ghidra_r3 != 1):
    sys.exit(1)
elif (input_arg != 100) and (ghidra_r3 != 0):
    sys.exit(1)


# Create a Unicorn emulator. 
unicorn = smallworld.emulators.UnicornEmulator(platform)

# Emulate our machine
unicorn_machine = machine.emulate(unicorn)

# read out r3
unicorn_r3 = unicorn_machine.get_cpu().r3.get()

# check that our function behaves the way we expect
if (input_arg == 100) and (unicorn_r3 != 1):
    sys.exit(1)
elif (input_arg != 100) and (unicorn_r3 != 0):
    sys.exit(1)

# # Create an angr emulator. 
# angr = smallworld.emulators.AngrEmulator(platform)

# # Emulate our machine
# angr_machine = machine.emulate(angr)

# # read out r3
# angr_r3 = angr_machine.get_cpu().r3.get()

# # check that our function behaves the way we expect
# if (input_arg == 100) and (angr_r3 != 1):
#     sys.exit(1)
# elif (input_arg != 100) and (angr_r3 != 0):
#     sys.exit(1)

