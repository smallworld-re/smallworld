import logging
import sys
import typing

import smallworld

# Set up logging and hinting
smallworld.logging.setup_logging(level=logging.INFO)

# Define the platform
platform = smallworld.platforms.Platform(
    smallworld.platforms.Architecture.SUPERH_SH2A_FPU,
    smallworld.platforms.Byteorder.BIG,
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
emulator = smallworld.emulators.PandaEmulator(platform)
emulator.add_exit_point(cpu.pc.get() + code.get_capacity())

# PANDA is real QEMU, which does not fold the delay slot into its parent: it
# translates each 2-byte SuperH instruction on its own and implements `bra` by
# stashing the target in `delayed_pc`, then letting the following instruction
# retire normally before the jump takes effect.  So where every pcode-derived
# backend attributes the delay slot's write to the `bra` at 0x1008, PANDA
# attributes it to the delay slot's own address, 0x100a.
expected_writes: typing.Dict[int, int] = {0x100A: 1, 0x1016: 1, 0x1020: 1}
actual_writes: typing.Dict[int, int] = dict()


def hook_memory_write(emu, addr, size, data):
    pc = emu.read_register("pc")
    actual_writes[pc] = 1 if pc not in actual_writes else actual_writes[pc] + 1


emulator.hook_memory_write(0x2000, 0x2004, hook_memory_write)

# ... and for the same reason an instruction hook placed on a delay slot does
# fire, at the delay slot's own address.  That makes three distinct delay-slot
# models in this one scenario: Ghidra fires no hook at all, angr fires one but
# reports the parent branch's pc (0x1008/0x1018), and PANDA fires one at
# 0x100a/0x101a.  PANDA also visits the two in address order - the `bra` hook
# runs before the delay-slot hook - rather than in the architectural order where
# the delay slot logically completes first.
expected_delay_slots: typing.Dict[int, int] = {0x100A: 1, 0x101A: 1}
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
