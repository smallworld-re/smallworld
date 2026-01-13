import logging

import smallworld

# Set up logging and hinting
smallworld.logging.setup_logging(level=logging.INFO)

# Define the platform
platform = smallworld.platforms.Platform(
    smallworld.platforms.Architecture.X86_32, smallworld.platforms.Byteorder.LITTLE
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
cpu.eip.set(code.address)

# Push a return address and arguments onto the stack
stack.push_integer(0x44444444, 4, None)  # Argument 7
stack.push_integer(0x01010101, 4, None)  # Argument 6
stack.push_integer(0x33333333, 4, None)  # Argument 5
stack.push_integer(0x01010101, 4, None)  # Argument 4
stack.push_integer(0x22222222, 4, None)  # Argument 3
stack.push_integer(0x01010101, 4, None)  # Argument 2
stack.push_integer(0x11111111, 4, None)  # Argument 1
stack.push_integer(0x01010101, 4, None)  # Return address
stack.write_bytes(
    0x2500, b"\xff\xff\xff\xff"
)  # ensure writing below sp won't modify sp

# Configure the stack pointer
rsp = stack.get_pointer()
cpu.esp.set(rsp)

# Emulate
emulator = smallworld.emulators.AngrEmulator(platform)
emulator.enable_linear()
emulator.add_exit_point(cpu.eip.get() + code.get_capacity())
final_machine = machine.emulate(emulator)

# read out the final state
cpu = final_machine.get_cpu()
print(cpu.eax)
