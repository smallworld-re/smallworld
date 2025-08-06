import logging

import smallworld

# Types
from smallworld.state.cpus.arm import ARM
from smallworld.state.memory.stack.arm import ARM32Stack

# Logging/hinting
smallworld.logging.setup_logging(level=logging.INFO)
smallworld.hinting.setup_hinting(stream=True, verbose=True)
log = logging.getLogger("smallworld")

###################
# HARNESS CONFIGURATION

# Machine
machine = smallworld.state.Machine()

# Code
with open("./zephyr.elf", "rb") as f:
    code = smallworld.state.memory.code.Executable.from_elf(f, page_size=1)
    machine.add(code)

# CPU
cpu: ARM = smallworld.state.cpus.CPU.for_platform(code.platform)
machine.add(cpu)

# Emulator
emulator = smallworld.emulators.UnicornEmulator(code.platform)

# Entry point / exit point
entry_point = code.get_symbol_value("smallworld_bug")
exit_point = 0x102368  # End of smallworld_bug, found via reverse engineering
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
buffer_memory = smallworld.state.memory.RawMemory.from_bytes(
    input_bytes, buffer_memory_address
)
machine.add(buffer_memory)

# Pass the buffer to smallworld_bug
cpu.r0.set(buffer_memory_address)
cpu.r1.set(buffer_memory_address)

###################
# HARNESS EXECUTION
for step in machine.step(emulator):
    pass

###################
# DEBUGGING INFO

# Extract changes to buffer
buffer_memory.extract(emulator)
output_bytes = buffer_memory.to_bytes(byteorder=code.platform.byteorder)
print(f"Buffer: {output_bytes}")
