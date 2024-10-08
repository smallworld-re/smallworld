import sys

import smallworld
import logging

# Set up logging and hinting
smallworld.logging.setup_logging(level=logging.INFO)
smallworld.hinting.setup_hinting(stream=True, verbose=True)

# Define the platform
platform = smallworld.platforms.Platform(
    smallworld.platforms.Architecture.MIPS32, smallworld.platforms.Byteorder.BIG
)

# Create a machine
machine = smallworld.state.Machine()

# Create a CPU
cpu = smallworld.state.cpus.CPU.for_platform(platform)
machine.add(cpu)

# Load and add code into the state
code = smallworld.state.memory.code.Executable.from_filepath("hooking.mips.bin", address=0x1000)
machine.add(code)

# Create a stack and add it to the state
stack = smallworld.state.memory.stack.Stack.for_platform(platform, 0x2000, 0x4000)
machine.add(stack)

# Set the instruction pointer to the code entrypoint 
cpu.pc.set(code.address + 8)

# Push a return address onto the stack
stack.push_integer(0xFFFFFFFF, 4, "fake return address")

# Configure the stack pointer
sp = stack.get_pointer()
cpu.sp.set(sp)

# Configure gets model
def gets_model(emulator: smallworld.emulators.Emulator) -> None:
    s = emulator.read_register("a0")
    v = input().encode("utf-8") + b"\0"
    try:
        emulator.write_memory_content(s, v) 
    except:
        raise smallworld.exceptions.AnalysisError(f"Failed writing {len(v)} bytes to {hex(s)} ")

gets = smallworld.state.models.ImplementedModel(0x1000, gets_model)
machine.add(gets)

# Configure puts model
def puts_model(emulator: smallworld.emulators.Emulator) -> None:
    # Reading a block of memory from angr will fail,
    # since values beyond the string buffer's bounds
    # are guaranteed to be symbolic.
    #
    # Thus, we must step one byte at a time.
    s = emulator.read_register("a0")
    v = b""
    try:
        b = emulator.read_memory_content(s, 1)
    except smallworld.exceptions.SymbolicValueError:
        b = None
    while b is not None and b != b"\x00":
        v = v + b
        s = s + 1
        try:
            b = emulator.read_memory_content(s, 1)
        except smallworld.exceptions.SymbolicValueError:
            b = None
    if b is None:
        raise smallworld.exceptions.SymbolicValueError(f"Symbolic byte at {hex(s)}")
    print(v)
puts = smallworld.state.models.ImplementedModel(0x1004, puts_model)
machine.add(puts)

# Emulate
emulator = smallworld.emulators.AngrEmulator(platform)
emulator.enable_linear()
emulator.add_exit_point(code.address + code.get_capacity())
final_machine = machine.emulate(emulator)
