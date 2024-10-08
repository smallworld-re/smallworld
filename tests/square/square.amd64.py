import sys

"""
python square.amd64.py square.amd64.bin 42 [step]

That last optional arg will run in single step mode.

"""

import smallworld
import logging
import copy

#smallworld.logging.setup_logging(level=logging.DEBUG)
smallworld.logging.setup_logging(level=logging.INFO) 
smallworld.hinting.setup_hinting(level=logging.DEBUG) 


machine = smallworld.state.Machine()
code = smallworld.state.memory.code.Executable.from_filepath(
    "square.amd64.bin", address=0x1000
)
machine.add(code)

platform = smallworld.platforms.Platform(
    smallworld.platforms.Architecture.X86_64, smallworld.platforms.Byteorder.LITTLE
)

cpu = smallworld.state.cpus.CPU.for_platform(platform)


cpu.rip.set(0x1000)
    

if len(sys.argv) == 2 and sys.argv[1] == "analyze":
    machine.add(cpu)
    colrz = smallworld.analyses.ColorizerAnalysis()
    machine.analyze(colrz)

else:

    emulator = smallworld.emulators.UnicornEmulator(platform)
    emulator.add_exit_point(cpu.rip.get() + 5)
    cpu.edi.set(int(sys.argv[1]))
    machine.add(cpu)

    if len(sys.argv) == 3 and sys.argv[2] == "step":
        for final_machine in machine.step(emulator):
            pass
    else:
        final_machine = machine.emulate(emulator)

    cpu = final_machine.get_cpu()
    print(cpu.eax.get())

