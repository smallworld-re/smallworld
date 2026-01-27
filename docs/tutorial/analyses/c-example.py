import copy
import logging

import smallworld
from smallworld.analyses import Colorizer
from smallworld.analyses.colorizer import randomize_uninitialized
from smallworld.hinting.hints import DynamicMemoryValueHint, DynamicRegisterValueHint

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
    open("c-example", "rb"), address=base_address
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


the_color = None


def collect_hints(hint):
    global the_color
    if hint.pc == 0x1238:
        print(f"First pass, color in rdi @ pc=0x{hint.pc:x} is {hint.color}")
        the_color = hint.color
    # print(hint)


# first time through to figure out color for rax/rdi
# at instruction
#   0x00001238      mov rdi, rax,
# immediately prior to call to system.
hinter = smallworld.hinting.Hinter()
hinter.register(DynamicMemoryValueHint, collect_hints)
hinter.register(DynamicRegisterValueHint, collect_hints)
c = Colorizer(hinter, num_insns=1000, exec_id=1)
machine_copy = copy.deepcopy(machine)
perturbed_machine = randomize_uninitialized(machine_copy, 1234)
c.run(perturbed_machine)


def collect_hints2(hint):
    global the_color
    if hint.color == the_color and hint.message == "read-def":
        print(
            f"Second pass, first obs of color {the_color} is pc=0x{hint.pc:x}, in {hint.reg_name}"
        )


# second time through to figure out when
# we first saw that color
hinter = smallworld.hinting.Hinter()
hinter.register(DynamicMemoryValueHint, collect_hints2)
hinter.register(DynamicRegisterValueHint, collect_hints2)
c = Colorizer(hinter, num_insns=1000, exec_id=1)
machine_copy = copy.deepcopy(machine)
perturbed_machine = randomize_uninitialized(machine_copy, 1234)
c.run(perturbed_machine)
