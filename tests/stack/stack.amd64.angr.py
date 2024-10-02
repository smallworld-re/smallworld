import logging

import smallworld

smallworld.logging.setup_logging(level=logging.INFO)

# Define the platform
platform = smallworld.platforms.Platform(
    smallworld.platforms.Architecture.X86_64, smallworld.platforms.Byteorder.LITTLE
)

# Create a machine
machine = smallworld.state.Machine()

# create a CPU
cpu = smallworld.state.cpus.CPU.for_platform(platform)
machine.add(cpu)

# load and add code into the state and set ip
code = smallworld.state.memory.code.Executable.from_filepath(
    "stack.amd64.bin", address=0x1000
)
machine.add(code)
cpu.rip.set(code.address)

# initialize some values
cpu.rdi.set(0x11111111)
cpu.rdx.set(0x22222222)
cpu.r8.set(0x33333333)

# create a stack and push a value
stack = smallworld.state.memory.stack.Stack.for_platform(platform, 0x2000, 0x4000)
stack.push_integer(0xFFFFFFFF, 8, "fake return address")
stack.push_integer(0x44444444, 8, None)

# rsp points to the next free stack slot
rsp = stack.get_pointer() + 15
cpu.rsp.set(rsp)

# add the stack into memory
machine.add(stack)

# emulate
emulator = smallworld.emulators.AngrEmulator(platform)
emulator.add_exit_point(cpu.rip.get() + 12)
emulator.enable_linear()
final_machine = machine.emulate(emulator)

# read out the final state
final_cpu = final_machine.get_cpu()
print(final_cpu.rax.get())
