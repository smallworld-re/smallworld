import logging

import smallworld

# import angr
# import pypcode


smallworld.logging.setup_logging(level=logging.INFO)
smallworld.hinting.setup_hinting(verbose=True, stream=True, file=None)

# Define the platform
platform = smallworld.platforms.Platform(
    smallworld.platforms.Architecture.XTENSA, smallworld.platforms.Byteorder.LITTLE
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
cpu.a2.set(0x1)
cpu.a3.set(arg1)
cpu.a4.set(len(data) - 1)


def syscall_hook(emu: smallworld.emulators.Emulator, number: int) -> None:
    print(f"Executing syscall {number}")


def write_hook(emu: smallworld.emulators.Emulator) -> None:
    print("Executing a write syscall")


def successor_func(state, **kwargs):
    if "irsb" in kwargs and kwargs["irsb"] is not None:
        irsb = kwargs["irsb"]
    else:
        irsb = state.block().vex

    for op in irsb._ops:
        print(op.opcode)

    kwargs["irsb"] = irsb
    return state.project.factory.successors(state, **kwargs)


emulator = smallworld.emulators.AngrEmulator(platform, successors=successor_func)
emulator.hook_syscalls(syscall_hook)
emulator.hook_syscall(4, write_hook)

# Emulate
emulator.enable_linear()
emulator.add_exit_point(cpu.pc.get() + code.get_capacity())
final_machine = machine.emulate(emulator)
