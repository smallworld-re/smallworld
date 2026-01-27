import copy
import functools
import logging

import smallworld
from smallworld import hinting
from smallworld.analyses import Colorizer, ColorizerReadWrite, ColorizerSummary
from smallworld.analyses.colorizer import randomize_uninitialized
from smallworld.hinting.hints import (
    DynamicMemoryValueSummaryHint,
    DynamicRegisterValueSummaryHint,
)

smallworld.logging.setup_logging(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# configure the platform for emulation
platform = smallworld.platforms.Platform(
    smallworld.platforms.Architecture.X86_64, smallworld.platforms.Byteorder.LITTLE
)

machine = smallworld.state.Machine()

cpu = smallworld.state.cpus.CPU.for_platform(platform)

base_address = 0x0
code = smallworld.state.memory.code.Executable.from_elf(
    open(f"c-example", "rb"), address=base_address
)
machine.add(code)

stack = smallworld.state.memory.stack.Stack.for_platform(platform, 0x10000, 0x4000)
machine.add(stack)
rsp = stack.get_pointer()
cpu.rsp.set(rsp)

entry_point = 0x1149 + base_address

# call to "system"
exit_point = 0x123B

cpu.rip.set(entry_point)
machine.add(cpu)
machine.add_exit_point(exit_point)

printf = smallworld.state.models.Model.lookup(
    "printf", platform, smallworld.platforms.ABI.SYSTEMV, 0x1040 + base_address
)
machine.add(printf)
printf.allow_imprecise = True
code.update_symbol_value("printf", printf._address)

# New and interesting stuff follows:

ha = {}


def collect_hints(hint):
    global ha
    if (
        type(hint) is DynamicMemoryValueSummaryHint
        or type(hint) is DynamicRegisterValueSummaryHint
    ):
        if hint.color not in ha:
            ha[hint.color] = []
        ha[hint.color].append(hint)


hinter = smallworld.hinting.Hinter()
hinter.register(DynamicMemoryValueSummaryHint, collect_hints)
hinter.register(DynamicRegisterValueSummaryHint, collect_hints)

cs = ColorizerSummary(hinter)
# crw = ColorizerReadWrite(hinter)
# analyses = [cs, crw]

for i in range(1, 5):
    logger.info(f"\nmicro exec number {i}")
    c = Colorizer(hinter, num_insns=1000, exec_id=i)
    machine_copy = copy.deepcopy(machine)
    perturbed_machine = randomize_uninitialized(machine_copy, 1234 + i)
    c.run(perturbed_machine)

cs.run(perturbed_machine)

mc = 0
for color in ha.keys():
    mc = max(color, mc)

for color in range(1, mc + 1):
    print(f"\ncolor={color}")
    ha[color].sort(key=lambda h: f"{h.pc}-{h.message}")
    for h in ha[color]:
        print(f"  pc=0x{h.pc:x}  {h}")
