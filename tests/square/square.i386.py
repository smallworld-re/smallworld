import sys

"""
python square.amd64.py square.amd64.bin 42 [step]

That last optional arg will run in single step mode.

"""

import smallworld
import logging
import copy

smallworld.logging.setup_logging(level=logging.INFO) 

machine = smallworld.state.Machine()
code = smallworld.state.memory.code.Executable.from_filepath(
    "square.amd64.bin", address=0x1000
)
machine.add(code)

platform = smallworld.platforms.Platform(
    smallworld.platforms.Architecture.X86_32, smallworld.platforms.Byteorder.LITTLE
)

cpu = smallworld.state.cpus.CPU.for_platform(platform)

cpu.eip.set(0x1000)
cpu.edi.set(int(sys.argv[1]))

machine.add(cpu)

emulator = smallworld.emulators.UnicornEmulator(platform)
emulator.add_exit_point(cpu.eip.get() + 5)

if len(sys.argv) == 3 and sys.argv[2] == "step":
    machine.apply(emulator)
    while True:
        try:
            emulator.step()
        except smallworld.exceptions.EmulationBounds:
            print("emulation complete; encountered exit point or went out of bounds")
            break
        except Exception as e:
            print(f"emulation ended; raised exception {e}")
            break

    final_machine = copy.deepcopy(machine)
    final_machine.extract(emulator)

else:
    final_machine = machine.emulate(emulator)

cpu = final_machine.get_cpu()
print(cpu.eax.get())

