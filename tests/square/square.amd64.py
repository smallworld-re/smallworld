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

import pdb
pdb.set_trace()

cpu.edi.set(int(sys.argv[-1]))


assert (cpu.edi.get() == int(sys.argv[-1]))
assert (cpu.rdi.get() == int(sys.argv[-1]))


machine.add(cpu)

import pdb
pdb.set_trace()

emulator = smallworld.emulators.UnicornEmulator(platform)
emulator.add_exit_point(cpu.rip.get() + 5)

final_machine = machine.emulate(emulator)

print(final_machine.cpu.eax)
