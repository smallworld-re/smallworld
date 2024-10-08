import sys

import smallworld
import logging

smallworld.logging.setup_logging(level=logging.INFO) 
smallworld.hinting.setup_hinting(level=logging.DEBUG) 

# Create a machine
machine = smallworld.state.Machine()

# Load code and add to the machien
code = smallworld.state.memory.code.Executable.from_filepath(
    "square.amd64.bin", address=0x1000
)
machine.add(code)

# Define the platform
platform = smallworld.platforms.Platform(
    smallworld.platforms.Architecture.X86_64, smallworld.platforms.Byteorder.LITTLE
)

# Create a CPU for that platform
cpu = smallworld.state.cpus.CPU.for_platform(platform)

# Set the instruction pointer to the code entrypoint
cpu.rip.set(0x1000)
    

if len(sys.argv) == 2 and sys.argv[1] == "analyze":

    machine.add(cpu)
    colorizer = smallworld.analyses.ColorizerAnalysis()
    machine.analyze(colorizer)

else:

    # Initialize argument register
    cpu.rdi.set(int(sys.argv[1]))
    
    machine.add(cpu)

    emulator = smallworld.emulators.UnicornEmulator(platform)
    emulator.add_exit_point(cpu.rip.get() + 5)

    # Emulate
    if len(sys.argv) == 3 and sys.argv[2] == "step":
        for final_machine in machine.step(emulator):
            pass
    else:
        final_machine = machine.emulate(emulator)

    # Read out the final state
    cpu = final_machine.get_cpu()
    print(cpu.eax.get())

