import logging

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
emulator.add_exit_point(cpu.pc.get() + code.get_capacity())


def hook_memory_write(emu, addr, size, data):
    print("Hook!")


emulator.hook_memory_write(0x2000, 0x2004, hook_memory_write)


def hook_expected_instruction(emu):
    pc = emu.read_register("pc")
    print(f"Expected instruction at {hex(pc)}")


def hook_unexpected_instruction(emu):
    pc = emu.read_register("pc")
    raise Exception(f"Unexpected instruction at {hex(pc)}")


# Branch
emulator.hook_instruction(0x1010, hook_expected_instruction)
# Delay slot
emulator.hook_instruction(0x1014, hook_expected_instruction)
# Instruction skipped by branch
emulator.hook_instruction(0x1018, hook_unexpected_instruction)

final_machine = machine.emulate(emulator)

# idx = 0
# for final_machine in machine.step(emulator):
#    idx += 1
#    if final_machine.get_cpu().pc.get() == exit_point:
#        break
#    if idx == 10:
#        break

# read out the final state
cpu = final_machine.get_cpu()
print(hex(cpu.v0.get()))
