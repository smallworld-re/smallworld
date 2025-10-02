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
cpu.edi.set_label("arg1")

# Add constraints
rdi = cpu.rdi.to_symbolic(platform.byteorder)
lo = claripy.BVV(1, 64)
hi = claripy.BVV(4, 64)

expr1 = claripy.UGE(rdi, lo)
expr2 = claripy.UGE(hi, rdi)
machine.add_constraint(expr1)
machine.add_constraint(expr2)

# Emulate
emulator = smallworld.emulators.AngrEmulator(platform)
emulator.enable_linear()
emulator.add_exit_point(cpu.rip.get() + code.get_capacity())
final_machine = machine.emulate(emulator)

# read out the final state
cpu = final_machine.get_cpu()
print(cpu.eax)

eax = cpu.eax.get()
zero = claripy.BVV(0, 32)
lo = claripy.BVV(1, 32)
hi = claripy.BVV(16, 32)
bad = claripy.BVV(32, 32)

if emulator.satisfiable([eax == zero]):
    raise ValueError("Result should not be 0x0")
if not emulator.satisfiable([eax == lo]):
    raise ValueError("Result could be 0x1")
if not emulator.satisfiable([eax == hi]):
    raise ValueError("Result could be 0x10")
if emulator.satisfiable([eax == bad]):
    raise ValueError("Result should not be 0x20")
