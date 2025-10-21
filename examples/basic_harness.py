import copy
import logging
import sys
import typing

import smallworld
from smallworld import hinting
from smallworld.analyses import Colorizer, ColorizerSummary
from smallworld.analyses.colorizer import randomize_uninitialized
from smallworld.hinting import DynamicRegisterValueHint, DynamicRegisterValueSummaryHint

# setup logging and hinting
smallworld.logging.setup_logging(level=logging.INFO)
logger = logging.getLogger(__name__)

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

# set start instruction for analysis and an "exit point" at which to
# stop
cpu.pc.set(code.address)
machine.add_exit_point(code.address + code.get_capacity())

# add code and cpu to the machine
machine.add(code)
machine.add(cpu)

def collect_hints(hint):
    logger.info(hint)

hinter = hinting.Hinter()
hinter.register(DynamicRegisterValueSummaryHint, collect_hints)
hinter.register(DynamicRegisterValueHint, collect_hints)

seed = 123456
cs = ColorizerSummary(hinter)
for i in range(10):
    c = Colorizer(hinter, num_insns=10, exec_id=i)
    perturbed_machine = randomize_uninitialized(machine, seed + i, [])
    c.run(perturbed_machine)
# Technically, an analysis takes a `machine` arg but this one doesn't
# actually use it for anythihng.  This is because it just listens for
# colorizer hints.
cs.run(None)
