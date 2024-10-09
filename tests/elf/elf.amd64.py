import sys

import smallworld
import logging

# Set up logging and hinting
smallworld.logging.setup_logging(level=logging.DEBUG)
smallworld.hinting.setup_hinting(stream=True, verbose=True)

# Define the platform
platform = smallworld.platforms.Platform(
    smallworld.platforms.Architecture.X86_64, smallworld.platforms.Byteorder.LITTLE
)

# Create a machine
machine = smallworld.state.Machine()

# Create a CPU
cpu = smallworld.state.cpus.CPU.for_platform(platform)
machine.add(cpu)

# Load and add code into the state
with open("elf.amd64.elf", "rb") as f:
    code = smallworld.state.memory.code.Executable.from_elf(f)
    machine.add(code)
