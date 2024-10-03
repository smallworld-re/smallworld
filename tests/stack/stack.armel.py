import logging

import smallworld

smallworld.logging.setup_logging(level=logging.INFO)

# Define the platform
platform = smallworld.platforms.Platform(
    smallworld.platforms.Architecture.ARM_V5T, smallworld.platforms.Byteorder.LITTLE
)

# Create a machine
machine = smallworld.state.Machine()

# create a CPU
cpu = smallworld.state.cpus.CPU.for_platform(platform)
machine.add(cpu)

# load and add code into the state and set ip
code = smallworld.state.memory.code.Executable.from_filepath(
    "stack.armel.bin", address=0x1000
)
machine.add(code)
cpu.pc.set(code.address)

# initialize some values
cpu.r0.set(0x11111111)
cpu.r1.set(0x01010101)
cpu.r2.set(0x22222222)
cpu.r3.set(0x01010101)

# create a stack and push a value
stack = smallworld.state.memory.stack.Stack.for_platform(platform, 0x2000, 0x4000)
stack.push_integer(0x44444444, 4, None)
stack.push_integer(0x01010101, 4, None)
stack.push_integer(0x33333333, 4, None)

# rsp points to the next free stack slot
sp = stack.get_pointer()
cpu.sp.set(sp)

# add the stack into memory
machine.add(stack)

# emulate
emulator = smallworld.emulators.UnicornEmulator(platform)
emulator.add_exit_point(cpu.pc.get() + code.get_capacity())
final_machine = machine.emulate(emulator)

# read out the final state
final_cpu = final_machine.get_cpu()
print(hex(final_cpu.r0.get()))
