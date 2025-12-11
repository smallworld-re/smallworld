import copy
import logging
import sys
import typing

import smallworld
from smallworld import hinting
from smallworld.analyses import Colorizer, ColorizerReadWrite, ColorizerSummary
from smallworld.analyses.colorizer import randomize_uninitialized

# setup logging and hinting
smallworld.logging.setup_logging(level=logging.INFO)

# configure the platform for emulation
platform = smallworld.platforms.Platform(
    smallworld.platforms.Architecture.X86_64, smallworld.platforms.Byteorder.LITTLE
)

# create a machine
machine = smallworld.state.Machine()

# create a CPU and add it to the machine
cpu = smallworld.state.cpus.CPU.for_platform(platform)

# create an executable and add it to the machine
code = smallworld.state.memory.code.Executable.from_filepath(
    sys.argv[1], address=0x1000
)
machine.add(code)


machine.add_exit_point(code.address + code.get_capacity())
# set the instruction pointer to the entrypoint of our executable
cpu.rip.set(code.address)

machine.add(cpu)

hinter = hinting.Hinter()

analyses: typing.List[smallworld.analyses.Analysis] = [
    ColorizerSummary(hinter),
    ColorizerReadWrite(hinter),
]

seed = 123456

for i in range(10):
    c = Colorizer(hinter, num_insns=10, exec_id=i)
    machine_copy = copy.deepcopy(machine)
    perturbed_machine = randomize_uninitialized(machine_copy, seed + i, ["rbp", "rsp"])
    c.run(perturbed_machine)


smallworld.analyze(perturbed_machine, analyses)
