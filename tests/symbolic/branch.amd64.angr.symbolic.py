import logging
import pathlib

import claripy

import smallworld

# Set up logging and hinting
smallworld.logging.setup_logging(level=logging.INFO)

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
path = pathlib.Path(__file__)
basename = path.name.split(".")[0]
binfile = path.parent.parent / basename / (basename + ".amd64.bin")
code = smallworld.state.memory.code.Executable.from_filepath(
    binfile.as_posix(), address=0x1000
)
machine.add(code)

# Set the instruction pointer to the code entrypoint
cpu.rip.set(code.address)

# Initialize argument registers
cpu.rdi.set_label("arg1")
rdi = cpu.rdi.to_symbolic(platform.byteorder)

# Emulate
emulator = smallworld.emulators.AngrEmulator(platform)
emulator.enable_linear()
machine.add_exit_point(cpu.rip.get() + code.get_capacity() - 1)
final_machine = machine.emulate(emulator)

# read out the final state
cpu = final_machine.get_cpu()
print(cpu.eax)
eax = cpu.eax.get()

one = claripy.BVV(1, 32)
hundred = claripy.BVV(100, 64)

if not emulator.satisfiable([rdi == hundred, eax == one]):
    raise ValueError("Bad Unsat: rdi == 100 && eax == 1")
if emulator.satisfiable([rdi != hundred, eax == one]):
    raise ValueError("Bad Sat: rdi != 100 && eax == 1")
if emulator.satisfiable([rdi == hundred, eax != one]):
    raise ValueError("Bad Sat: rdi == 100 && eax != 1")
if not emulator.satisfiable([rdi != hundred, eax != one]):
    raise ValueError("Bad Unsat: rdi != 100 && eax != 1")
