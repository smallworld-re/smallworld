import logging

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
emulator = smallworld.emulators.AngrEmulator(code.platform)
emulator.enable_linear()

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
input_bytes = b"8x88888\xE18\x17\xF3\x1Faaa"
# input_bytes = b"\x7F8888888=.3a"
buffer_memory = smallworld.state.memory.Memory(buffer_memory_address, len(input_bytes))
buffer_memory[0] = smallworld.state.BytesValue(input_bytes, "input_buffer")
machine.add(buffer_memory)

# Pass the buffer to smallworld_bug
cpu.r0.set(buffer_memory_address)
cpu.r1.set(buffer_memory_address)

###################
# HARNESS EXECUTION

machine.emulate(emulator)

###################
# DEBUGGING INFO

# Investigate crashing instruction
cpu.extract(emulator)
r6 = cpu.r6.get()
print(f"r6: {hex(r6)}")
r4 = cpu.r4.get()
print(f"r4: {hex(r4)}")
r8 = cpu.r8.get()
print(f"r8: {r8}")

# Investigate symbolic stack memory
stack_memory = emulator.read_memory_symbolic(0x2000, 0x4000)
print(f"Symbolic stack memory: {stack_memory}")

# Investigate memory above stack
stack_memory = emulator.read_memory_symbolic(0x6000, 0x1000)
print(f"After stack memory: {stack_memory}")
