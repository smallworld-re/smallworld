import logging
import sys
import typing

import smallworld

# Set up logging and hinting
smallworld.logging.setup_logging(level=logging.INFO)

# Define the platform
platform = smallworld.platforms.Platform(
    smallworld.platforms.Architecture.SUPERH_SH4, smallworld.platforms.Byteorder.BIG
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
    .replace(".pcode", "")
    .replace(".styx", ""),
    address=0x1000,
)
machine.add(code)

# Add a little memory for us to use
data = smallworld.state.memory.RawMemory.from_bytes(b"\0" * 4, 0x2000)
machine.add(data)

# Set the instruction pointer to the code entrypoint
cpu.pc.set(code.address)

# Emulate
exit_point = cpu.pc.get() + code.get_capacity()
emulator = smallworld.emulators.GhidraEmulator(platform)
emulator.add_exit_point(cpu.pc.get() + code.get_capacity())

# SuperH's delay slot is folded into its parent branch by every pcode-derived
# backend, so the write issued by the delay slot at 0x100a is attributed to the
# `bra` at 0x1008 rather than to the delay slot itself.
expected_writes: typing.Dict[int, int] = {0x1008: 1, 0x1016: 1, 0x1020: 1}
actual_writes: typing.Dict[int, int] = dict()


def hook_memory_write(emu, addr, size, data):
    pc = emu.read_register("pc")
    actual_writes[pc] = 1 if pc not in actual_writes else actual_writes[pc] + 1


emulator.hook_memory_write(0x2000, 0x2004, hook_memory_write)

# ... and for the same reason no instruction hook fires on a delay slot.
expected_delay_slots: typing.Dict[int, int] = dict()
actual_delay_slots: typing.Dict[int, int] = dict()


def hook_expected_instruction(emu):
    pc = emu.read_register("pc")
    actual_delay_slots[pc] = (
        1 if pc not in actual_delay_slots else actual_delay_slots[pc] + 1
    )


def hook_unexpected_instruction(emu):
    pc = emu.read_register("pc")
    raise Exception(f"Unexpected instruction at {hex(pc)}")


# Delay slot instructions
emulator.hook_instruction(0x100A, hook_expected_instruction)
emulator.hook_instruction(0x101A, hook_expected_instruction)

# Instructions skipped by branches
emulator.hook_instruction(0x100C, hook_unexpected_instruction)
emulator.hook_instruction(0x100E, hook_unexpected_instruction)
emulator.hook_instruction(0x101C, hook_unexpected_instruction)

try:
    for final_machine in machine.step(emulator):
        pass
except smallworld.exceptions.EmulationStop:
    pass

# read out the final state
cpu = final_machine.get_cpu()

bad = False
if cpu.r0.get() != 4:
    print(f"Expected return value of 4, got {cpu.r0.get()}", file=sys.stderr)
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
