import copy
import logging
import functools

import smallworld
from smallworld import hinting
from smallworld.analyses import Colorizer, ColorizerReadWrite
from smallworld.platforms.defs.platformdef import RegisterAliasDef, RegisterDef

from smallworld.analyses.colorizer import randomize_uninitialized
from smallworld.hinting.hints import (
    DynamicMemoryValueSummaryHint,
    DynamicRegisterValueSummaryHint
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
exit_point = 0x123b

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

hinter = smallworld.hinting.Hinter()
crw = ColorizerReadWrite(hinter)

c = Colorizer(hinter, num_insns=1000, exec_id=1)    
machine_copy = copy.deepcopy(machine)
perturbed_machine = randomize_uninitialized(
    machine_copy, 1234
)
c.run(perturbed_machine)
crw.run(perturbed_machine)

# directly ask for a derivation of the value in rax in instruction 0x1238
der = crw.graph.derive(0x1238, True, RegisterDef("rax", 8))
print(der)


