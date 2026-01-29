import logging

from unicorn.unicorn import Uc

import smallworld
from smallworld.state.cpus.arm import ARM
from smallworld.state.memory.stack.arm import ARM32Stack

# Logging/hinting
smallworld.logging.setup_logging(level=logging.INFO)
log = logging.getLogger("smallworld")

###################
# HARNESS CONFIGURATION

# Machine
machine = smallworld.state.Machine()

# Code
zephyr_elf = open("./zephyr.elf", "rb")
code = smallworld.state.memory.code.Executable.from_elf(zephyr_elf, page_size=1)
machine.add(code)

# CPU
cpu: ARM = smallworld.state.cpus.CPU.for_platform(code.platform)
machine.add(cpu)

# Emulator
emulator = smallworld.emulators.UnicornEmulator(code.platform)

# Entry point / exit point
entry_point = code.get_symbol_value("smallworld_bug")
exit_point = 0x103DD8  # End of smallworld_bug, found via reverse engineering
cpu.pc.set(entry_point)
emulator.add_exit_point(exit_point)

# Stack
stack: ARM32Stack = smallworld.state.memory.stack.Stack.for_platform(
    cpu.platform, 0x2000, 0x4000
)
machine.add(stack)
sp = stack.get_pointer()
cpu.sp.set(sp)

# Input buffer
buffer_memory_address = 0x1000
input_bytes = b"abcdefghijklmnop"
buffer_memory = smallworld.state.memory.Memory(buffer_memory_address, len(input_bytes))
buffer_memory[0] = smallworld.state.BytesValue(input_bytes, "input_buffer")
machine.add(buffer_memory)

# Pass the buffer to smallworld_bug
cpu.r0.set(buffer_memory_address)
cpu.r1.set(buffer_memory_address)

###################
# FUZZING


def input_callback(uc: Uc, input, persistent_round, data):
    if len(input) > 0x1000:
        return False
    uc.mem_write(buffer_memory_address, input)


machine.fuzz(emulator, input_callback)
