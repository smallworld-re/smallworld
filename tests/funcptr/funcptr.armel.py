import logging

import smallworld
from smallworld.state.models.cstd import ArgumentType
from smallworld.state.models.funcptr import FunctionPointer

# Set up logging and hinting
smallworld.logging.setup_logging(level=logging.DEBUG)

# Define the platform
platform = smallworld.platforms.Platform(
    smallworld.platforms.Architecture.ARM_V5T, smallworld.platforms.Byteorder.LITTLE
)

# Create a machine
machine = smallworld.state.Machine()

# Create a CPU
cpu: smallworld.state.cpus.ARMv5T = smallworld.state.cpus.CPU.for_platform(platform)
machine.add(cpu)

# Load and add code into the state
code = smallworld.state.memory.code.Executable.from_elf(
    open("funcptr.armel.elf", "rb"), page_size=1
)
machine.add(code)

# Create a stack and add it to the state
stack: smallworld.state.memory.stack.ARMv5tStack = (
    smallworld.state.memory.stack.Stack.for_platform(platform, 0x2000, 0x4000)
)
machine.add(stack)

# Set the instruction pointer to the code entrypoint
cpu.pc.set(code.get_symbol_value("main"))

# Push a return address onto the stack
stack.push_integer(0xFFFFFFFF, 4, "fake return address")

# Configure the stack pointer
sp = stack.get_pointer()
cpu.sp.set(sp)

# Configure models
CALLER_ADDR = 0x1046C
QSORT_ADDR = 0x10340
PRINTF_ADDR = 0x10328
CALLEE_RET_ADDR = 0x10464
MAIN_RET_ADDR = 0x105D0


class CallerModel(smallworld.state.models.Model):
    name = "caller"
    platform = platform
    abi = smallworld.platforms.ABI.NONE

    def model(self, emulator: smallworld.emulators.Emulator) -> None:
        callee = emulator.read_register("r0")
        FunctionPointer(callee, CALLEE_RET_ADDR, [], ArgumentType.VOID, platform).call(
            emulator, []
        )


caller = CallerModel(CALLER_ADDR)
machine.add(caller)

qsort = smallworld.state.models.Model.lookup(
    "qsort", platform, smallworld.platforms.ABI.SYSTEMV, QSORT_ADDR
)
machine.add(qsort)

printf = smallworld.state.models.Model.lookup(
    "printf", platform, smallworld.platforms.ABI.SYSTEMV, PRINTF_ADDR
)
machine.add(printf)

# Emulate
emulator = smallworld.emulators.UnicornEmulator(platform)
machine.add_exit_point(MAIN_RET_ADDR)
for step in machine.step(emulator):
    pass
