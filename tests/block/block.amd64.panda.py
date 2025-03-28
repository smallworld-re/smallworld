import logging
import sys

import smallworld

# Set up logging and hinting
smallworld.logging.setup_logging(level=logging.INFO)
smallworld.hinting.setup_hinting(stream=True, verbose=True)

# Define the platform
platform = smallworld.platforms.Platform(
    smallworld.platforms.Architecture.X86_64, smallworld.platforms.Byteorder.LITTLE
)

# Create a machine
machine = smallworld.state.Machine()

# Create a CPU
cpu = smallworld.state.cpus.CPU.for_platform(platform)
machine.add(cpu)

# Load and add code into the state
code = smallworld.state.memory.code.Executable.from_filepath(
    __file__.replace(".py", ".bin").replace(".angr", "").replace(".panda", ""),
    address=0x1000,
)
machine.add(code)

# Set the instruction pointer to the code entrypoint
cpu.rip.set(code.address)

# Initialize argument registers
cpu.rdi.set(int(sys.argv[1]))
cpu.rsi.set(int(sys.argv[2]))

# Emulate
emulator = smallworld.emulators.PandaEmulator(platform)
emulator.add_exit_point(cpu.rip.get() + code.get_capacity())
print(f"Exit point at {hex(cpu.rip.get() + code.get_capacity())}")
machine.apply(emulator)
emulator.step_block()
emulator.step_block()
emulator.step_block()
emulator.step()
print(f"1={emulator.read_register('eax')}")
emulator.step()
print(f"2={emulator.read_register('edx')}")
emulator.step()
print(f"3={emulator.read_register('edx')}")
emulator.step()  # _block()
print(f"4={emulator.read_register('eax')}")
emulator.step_block()
print(f"5={emulator.read_register('edi')}")
emulator.run()
print(f"6={emulator.read_register('edi')}")
# final_machine = machine.emulate(emulator)

# read out the final state
# cpu = final_machine.get_cpu()
# print(hex(cpu.eax.get()))
