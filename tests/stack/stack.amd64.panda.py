import logging

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
code = smallworld.state.memory.code.Executable.from_filepath(
    __file__.replace(".py", ".bin")
    .replace(".angr", "")
    .replace(".panda", "")
    .replace(".pcode", ""),
    address=0x1000,
)
machine.add(code)

# Create a stack and add it to the state
stack = smallworld.state.memory.stack.Stack.for_platform(platform, 0x2000, 0x4000)
machine.add(stack)

# Set the instruction pointer to the code entrypoint
cpu.rip.set(code.address)

# Initialize argument registers
cpu.rdi.set(0x11111111)
cpu.rdx.set(0x22222222)
cpu.r8.set(0x33333333)

# Push a return address and an extra argument onto the stack
stack.push_integer(0x44444444, 8, None)
stack.push_integer(0xFFFFFFFF, 8, "fake return address")
stack.write_bytes(
    0x2500, b"\xff\xff\xff\xff"
)  # ensure writing below sp won't modify sp

# Configure the stack pointer
rsp = stack.get_pointer()
cpu.rsp.set(rsp)

# Emulate
emulator = smallworld.emulators.PandaEmulator(platform)
emulator.add_exit_point(cpu.rip.get() + code.get_capacity())
final_machine = machine.emulate(emulator)

# read out the final state
cpu = final_machine.get_cpu()
print(cpu.eax)
