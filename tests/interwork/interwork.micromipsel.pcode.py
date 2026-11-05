import logging
import sys

import smallworld

# Set up logging
smallworld.logging.setup_logging(level=logging.INFO)

# Define the platform
platform = smallworld.platforms.Platform(
    smallworld.platforms.Architecture.MIPS32_MICROMIPS,
    smallworld.platforms.Byteorder.LITTLE,
)

EXIT = 0xFFFF0
ARGUMENT = 5
# (n + 1) * 2 + 3; see interwork.micromips.elf.s.
EXPECTED = (ARGUMENT + 1) * 2 + 3


class Double(smallworld.state.models.Model):
    """Stands in for mips_double, which microMIPS code calls through jalr,
    so the model returns to microMIPS through an odd ra."""

    name = "mips_double"
    platform = platform
    abi = smallworld.platforms.ABI.NONE

    def model(self, emulator):
        emulator.write_register("v0", emulator.read_register("a0") * 2)


class AddThree(smallworld.state.models.Model):
    """Stands in for micro_add3, which MIPS32 code calls through jalr,
    so the model returns to MIPS32 through an even ra."""

    name = "micro_add3"
    platform = platform
    abi = smallworld.platforms.ABI.NONE

    def model(self, emulator):
        emulator.write_register("v0", emulator.read_register("a0") + 3)


def run(hooked=None):
    machine = smallworld.state.Machine()
    cpu = smallworld.state.cpus.CPU.for_platform(platform)
    machine.add(cpu)

    path = __file__.replace(".pcode.py", ".elf")
    with open(path, "rb") as f:
        code = smallworld.state.memory.code.Executable.from_elf(f, platform=platform)
    machine.add(code)
    for start, end in code.bounds:
        machine.add_bound(start, end)

    stack = smallworld.state.memory.stack.Stack.for_platform(platform, 0x8000, 0x4000)
    machine.add(stack)

    # __start is standard MIPS32 code; runs start in microMIPS otherwise.
    cpu.pc.set(code.entrypoint)
    cpu.isa_mode.set(0)
    cpu.a0.set(ARGUMENT)
    cpu.sp.set(stack.get_pointer())
    cpu.ra.set(EXIT)
    machine.add_exit_point(EXIT)

    if hooked is not None:
        machine.add(hooked(code.get_symbol_value(hooked.name)))

    final = machine.emulate(smallworld.emulators.GhidraEmulator(platform))
    return final.get_cpu()


bad = False
for hooked in (None, Double, AddThree):
    cpu = run(hooked)
    name = "unhooked" if hooked is None else f"{hooked.name} hooked"
    if cpu.v0.get() != EXPECTED:
        print(f"{name}: expected v0 = {EXPECTED}, got {cpu.v0.get()}", file=sys.stderr)
        bad = True
    # The last jump, jr to the even exit address, leaves MIPS32 selected.
    if cpu.isa_mode.get() != 0:
        print(
            f"{name}: expected isa_mode 0 at exit, got {cpu.isa_mode.get()}",
            file=sys.stderr,
        )
        bad = True

if bad:
    raise Exception("Test failed; see stderr for details")
print("Success!", file=sys.stderr)
