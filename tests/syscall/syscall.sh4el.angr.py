import logging

import smallworld

smallworld.logging.setup_logging(level=logging.INFO)

# Define the platform
platform = smallworld.platforms.Platform(
    smallworld.platforms.Architecture.SUPERH_SH4,
    smallworld.platforms.Byteorder.LITTLE,
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
stack.push_integer(0xFFFFFFFF, 4, None)

# set the stack pointer
cpu.sp.set(stack.get_pointer())

# Initialize call to write():
# - r3: the syscall number, but the blob loads that itself with `mov #4, r3`
# - r4: File descriptor 1 (stdout)
# - r5: Buffer containing output
# - r6: Size of output buffer
#
# Linux/SH's syscall convention is number in r3 and arguments in r4-r7, then r0
# and r1; see the comment in syscall.sh4.s for where that is verified from.
cpu.r4.set(0x1)
cpu.r5.set(arg1)
cpu.r6.set(len(data) - 1)


def syscall_hook(emu: smallworld.emulators.Emulator, number: int) -> None:
    print(f"Executing syscall {number}")


def write_hook(emu: smallworld.emulators.Emulator) -> None:
    print("Executing a write syscall")


emulator = smallworld.emulators.AngrEmulator(platform)
emulator.hook_syscalls(syscall_hook)
# 4 is __NR_write on Linux/SH, per linux-user/sh4/syscall.tbl.
emulator.hook_syscall(4, write_hook)

# Emulate
emulator.add_exit_point(cpu.pc.get() + code.get_capacity())
machine.emulate(emulator)
