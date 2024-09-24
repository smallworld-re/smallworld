import sys

import smallworld
import logging

smallworld.logging.setup_logging(level = logging.DEBUG)

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
cpu.edi.set(int(sys.argv[-1]))
machine.add(cpu)

emulator = smallworld.emulators.UnicornEmulator(platform)
final_machine = machine.emulate(emulator)

print(final_machine.cpu.eax)
