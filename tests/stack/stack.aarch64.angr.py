import logging

import smallworld

smallworld.logging.setup_logging(level=logging.INFO)

# Define the platform
platform = smallworld.platforms.Platform(
    smallworld.platforms.Architecture.AARCH64, smallworld.platforms.Byteorder.LITTLE
)

# Create a machine
machine = smallworld.state.Machine()

# create a CPU
cpu = smallworld.state.cpus.CPU.for_platform(platform)
machine.add(cpu)

# load and add code into the state and set ip
code = smallworld.state.memory.code.Executable.from_filepath(
    "stack.aarch64.bin", address=0x1000
)
machine.add(code)
cpu.pc.set(code.address)

# initialize some values
cpu.w0.set(0x11111111)
cpu.w1.set(0x01010101)
cpu.w2.set(0x22222222)
cpu.w3.set(0x01010101)
cpu.w4.set(0x33333333)
cpu.w5.set(0x01010101)
cpu.w6.set(0x44444444)
cpu.w7.set(0x01010101)

# create a stack and push a value
stack = smallworld.state.memory.stack.Stack.for_platform(platform, 0x2000, 0x4000)
stack.push_integer(0x55555555, 8, None)

# rsp points to the next free stack slot
sp = stack.get_pointer()
cpu.sp.set(sp)

# add the stack into memory
machine.add(stack)

# emulate
emulator = smallworld.emulators.AngrEmulator(platform)
emulator.enable_linear()
emulator.add_exit_point(cpu.pc.get() + 20)
final_machine = machine.emulate(emulator)


# read out the final state
final_cpu = final_machine.get_cpu()
print(hex(final_cpu.x0.get()))
