import logging
import sys

import smallworld

# setup logging and hinting
smallworld.logging.setup_logging(level=logging.INFO)
smallworld.hinting.setup_hinting(stream=True, verbose=True)

# configure the platform for emulation
platform = smallworld.platforms.Platform(
    smallworld.platforms.Architecture.X86_64, smallworld.platforms.Byteorder.LITTLE
)

# create a machine
machine = smallworld.state.Machine()

# create a CPU and add it to the machine
cpu = smallworld.state.cpus.CPU.for_platform(platform)

# create an executable and add it to the machine
code = smallworld.state.memory.code.Executable.from_filepath(
    sys.argv[1], address=0x1000
)
machine.add(code)

# set the instruction pointer to the entrypoint of our executable
cpu.rip.set(code.address)

machine.add(cpu)

# analyze
smallworld.helpers.analyze(machine)
