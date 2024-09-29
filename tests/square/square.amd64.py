import sys

"""
python square.amd64.py square.amd64.bin 42 [step]

That last optional arg will run in single step mode.

"""

import smallworld
import logging
import copy

smallworld.logging.setup_logging(level = logging.INFO) # DEBUG)

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
cpu.edi.set(int(sys.argv[2]))
machine.add(cpu)

emulator = smallworld.emulators.UnicornEmulator(platform)
emulator.add_exit_point(cpu.rip.get() + 5)

machine.apply(emulator)

if len(sys.argv) == 4 and sys.argv[3] == "step":
    while True:
        try:
            emulator.step_instruction()
        except smallworld.exceptions.EmulationBounds:
            print("emulation complete; encountered exit point or went out of bounds")
            break
        except Exception as e:
            print("emulation ended; raised exception {e}")
            break

    final_machine = copy.deepcopy(machine)
    final_machine.extract(emulator)

else:
    final_machine = machine.emulate(emulator)

cpu = final_machine.get_cpu()
print(cpu.eax.get())

