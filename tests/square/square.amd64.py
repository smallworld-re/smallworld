import sys

import smallworld
import logging

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
cpu.edi.set(int(sys.argv[-1]))
machine.add(cpu)

emulator = smallworld.emulators.UnicornEmulator(platform)
emulator.add_exit_point(cpu.rip.get() + 5)


machine.apply(emulator)

import pdb
pdb.set_trace()

while True:
    try:
        emulator.step_instruction()
    except Exception as e:
        print(e)
        import pdb
        pdb.set_trace()

machine_copy = copy.deepcopy(machine)



final_machine = machine.emulate(emulator)

cpu = final_machine.get_cpu()
print(cpu.eax.get())

