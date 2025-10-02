import logging

import smallworld

smallworld.logging.setup_logging(level=logging.INFO)

# Define the platform
platform = smallworld.platforms.Platform(
    smallworld.platforms.Architecture.MIPS32, smallworld.platforms.Byteorder.BIG
)

# create a state object
machine = smallworld.state.Machine()

# Create a CPU
cpu = smallworld.state.cpus.CPU.for_platform(platform)
machine.add(cpu)

# load and map code into the state and set ip
code = smallworld.state.memory.code.Executable.from_filepath(
    __file__.replace(".py", ".bin").replace(".angr", "").replace(".panda", ""),
    address=0x1000,
)
machine.add(code)
cpu.pc.set(code.address)

# create a stack and push a value
stack = smallworld.state.memory.stack.Stack.for_platform(platform, 0x2000, 0x1000)
machine.add(stack)

data = b"Hello, world!\n\0"
stack.push_bytes(data, None)
arg1 = stack.get_pointer()

# Push a fake return address
stack.push_integer(0xFFFFFFFF, 8, None)

# set the stack pointer
cpu.sp.set(stack.get_pointer())

# Initialize call to write():
# - edi: File descriptor 1 (stdout)
# - rsi: Buffer containing output
# - rdx: Size of output buffer
cpu.a0.set(0x1)
cpu.a1.set(arg1)
cpu.a2.set(len(data) - 1)


def syscall_hook(emu: smallworld.emulators.Emulator, number: int) -> None:
    print(f"Executing syscall {number}")


def write_hook(emu: smallworld.emulators.Emulator) -> None:
    print("Executing a write syscall")


emulator = smallworld.emulators.AngrEmulator(platform)
emulator.hook_syscalls(syscall_hook)
emulator.hook_syscall(4004, write_hook)

# Emulate
emulator.enable_linear()
machine.add_exit_point(cpu.pc.get() + code.get_capacity() - 4)
final_machine = machine.emulate(emulator)

# read out the final state
final_cpu = final_machine.get_cpu()
print(hex(final_cpu.pc.get()))
