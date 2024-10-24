import logging

import smallworld

smallworld.logging.setup_logging(level=logging.INFO)
smallworld.hinting.setup_hinting(verbose=True, stream=True, file=None)

# Define the platform
platform = smallworld.platforms.Platform(
    smallworld.platforms.Architecture.X86_64, smallworld.platforms.Byteorder.LITTLE
)

# create a state object
machine = smallworld.state.Machine()

# Create a CPU
cpu = smallworld.state.cpus.CPU.for_platform(platform)
machine.add(cpu)

# load and map code into the state and set ip
code = smallworld.state.memory.code.Executable.from_filepath(
    __file__.replace(".py", ".bin").replace(".angr", ""), address=0x1000
)
machine.add(code)

# create a stack and push a value
stack = smallworld.state.memory.stack.Stack.for_platform(platform, 0x2000, 0x1000)
machine.add(stack)


data = b"Hello, world!\n\0"
stack.push_bytes(data, None)
arg1 = stack.get_pointer()

# Push a fake return address
stack.push_integer(0xFFFFFFFF, 8, None)

# set the stack pointer
cpu.rsp.set(stack.get_pointer())

# Initialize call to write():
# - edi: File descriptor 1 (stdout)
# - rsi: Buffer containing output
# - rdx: Size of output buffer
cpu.edi.set(0x1)
cpu.rsi.set(arg1)
cpu.rdx.set(len(data) - 1)

# Emulate
emulator = smallworld.emulators.UnicornEmulator(platform)
emulator.add_exitpoint(cpu.rip.get() + code.get_capacity())
final_machine = machine.emulate(emulator)

# read out the final state
final_cpu = final_machine.get_cpu()
print(hex(final_cpu.eax.get()))
