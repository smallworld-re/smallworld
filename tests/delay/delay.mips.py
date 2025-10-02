import logging
import sys

import smallworld

# Set up logging and hinting
smallworld.logging.setup_logging(level=logging.INFO)

# Define the platform
platform = smallworld.platforms.Platform(
    smallworld.platforms.Architecture.MIPS32, smallworld.platforms.Byteorder.BIG
)

# Create a machine
machine = smallworld.state.Machine()

# Create a CPU
cpu = smallworld.state.cpus.CPU.for_platform(platform)
machine.add(cpu)

# Load and add code into the state
code = smallworld.state.memory.code.Executable.from_filepath(
    __file__.replace(".py", ".bin")
    .replace(".angr", "")
    .replace(".panda", "")
    .replace(".pcode", ""),
    address=0x1000,
)
machine.add(code)

# Add a little memory for us to use
data = smallworld.state.memory.RawMemory.from_bytes(b"\0" * 4, 0x2000)
machine.add(data)

# Set the instruction pointer to the code entrypoint
cpu.pc.set(code.address)

# Emulate
exit_point = cpu.pc.get() + code.get_capacity() - 4
emulator = smallworld.emulators.UnicornEmulator(platform)
machine.add_exit_point(exit_point)


expected_writes = {0x1010: 1, 0x1024: 2, 0x1038: 1}
actual_writes = dict()


def hook_memory_write(emu, addr, size, data):
    pc = emu.read_register("pc")
    if pc not in actual_writes:
        actual_writes[pc] = 1
    else:
        actual_writes[pc] += 1


emulator.hook_memory_write(0x2000, 0x2004, hook_memory_write)

expected_delay_slots = {0x1010: 1, 0x1024: 2, 0x102C: 1}
actual_delay_slots = dict()


def hook_expected_instruction(emu):
    pc = emu.read_register("pc")
    if pc not in actual_delay_slots:
        actual_delay_slots[pc] = 1
    else:
        actual_delay_slots[pc] += 1


def hook_unexpected_instruction(emu):
    pc = emu.read_register("pc")
    raise Exception(f"Unexpected instruction at {hex(pc)}")


# Delay slot instructions
emulator.hook_instruction(0x1010, hook_expected_instruction)
emulator.hook_instruction(0x1024, hook_expected_instruction)
emulator.hook_instruction(0x102C, hook_expected_instruction)
# Instructions skipped by branches
emulator.hook_instruction(0x1014, hook_unexpected_instruction)
emulator.hook_instruction(0x1018, hook_unexpected_instruction)
emulator.hook_instruction(0x1030, hook_unexpected_instruction)

# final_machine = machine.emulate(emulator)

try:
    for final_machine in machine.step(emulator):
        pass
except smallworld.exceptions.EmulationStop:
    pass

# read out the final state
cpu = final_machine.get_cpu()

bad = False
if cpu.v0.get() != 4:
    print(f"Expected return value of 4, got {cpu.v0.get()}", file=sys.stderr)
    bad = True

for addr, count in expected_writes.items():
    if addr not in actual_writes:
        print(
            f"Expected to see {count} writes at PC {hex(addr)}; saw none",
            file=sys.stderr,
        )
        bad = True
    elif count != actual_writes[addr]:
        print(
            f"Expected to see {count} writes at PC {hex(addr)}; saw {actual_writes[addr]}",
            file=sys.stderr,
        )
        bad = True

for addr, count in actual_writes.items():
    if addr not in expected_writes:
        print(f"Saw {count} unexpected writes at PC {hex(addr)}", file=sys.stderr)
        bad = True

for addr, count in expected_delay_slots.items():
    if addr not in actual_delay_slots:
        print(
            f"Expected to see {count} delay slots at PC {hex(addr)}; saw none",
            file=sys.stderr,
        )
        bad = True
    elif count != actual_delay_slots[addr]:
        print(
            f"Expected to see {count} delay slots at PC {hex(addr)}; saw {actual_delay_slots[addr]}",
            file=sys.stderr,
        )
        bad = True

for addr, count in actual_delay_slots.items():
    if addr not in expected_delay_slots:
        print(f"Saw {count} unexpected delay slots at PC {hex(addr)}", file=sys.stderr)
        bad = True

if bad:
    raise Exception("Test failed; see stderr for details")
else:
    print("Success!", file=sys.stderr)
