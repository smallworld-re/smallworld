import logging

import smallworld

# Set up logging and hinting
smallworld.logging.setup_logging(level=logging.INFO)

# Define the platform
platform = smallworld.platforms.Platform(
    smallworld.platforms.Architecture.MIPS32, smallworld.platforms.Byteorder.LITTLE
)

# Create a machine
machine = smallworld.state.Machine()

# Create a CPU
cpu = smallworld.state.cpus.CPU.for_platform(platform)
machine.add(cpu)

# Load and add core file into the state
filename = (
    __file__.replace(".py", ".elf.core")
    .replace(".angr", "")
    .replace(".panda", "")
    .replace(".pcode", "")
)
with open(filename, "rb") as f:
    code = smallworld.state.memory.code.Executable.from_elf_core(f, platform=platform)
    machine.add(code)
    code.populate_cpu(cpu)

# Load register ground truth
filename = (
    __file__.replace(".py", ".elf.registers")
    .replace(".angr", "")
    .replace(".panda", "")
    .replace(".pcode", "")
)

expected_regs = dict()

with open(filename, "r") as rfile:
    text = rfile.read()
lines = text.split("\n")
# Of course MIPS is a pain.
# It prints its register file in a grid, not in a single column.
for i in range(0, len(lines), 2):
    if i + 1 >= len(lines):
        break
    names = lines[i]
    values = lines[i + 1]

    # The start of both lines is a header or spacing
    _, _, names = names.split(" ", maxsplit=2)
    _, _, values = values.split(" ", maxsplit=2)

    names = names.lstrip() + " "
    values = values.lstrip() + " "

    while names != "":
        name, names = names.split(" ", maxsplit=1)
        value, values = values.split(" ", maxsplit=1)

        if not value.startswith("<"):
            expected_regs[name] = int(value, 16)

        names = names.lstrip()
        values = values.lstrip()


bad = False
for reg, val in code.prstatus._registers.items():
    if reg not in expected_regs:
        print(f"ERROR: {reg} was not in the register dump from GDB")
        bad = True
        continue
    if val != expected_regs[reg]:
        print(f"ERROR: {reg} expected: {hex(expected_regs[reg])}, actual: {hex(val)}")
        bad = True
        continue
    cpu_val = getattr(cpu, reg).get()
    if val != cpu_val:
        print(f"ERROR: CPU had wrong value for {reg}: {cpu_val}")
        bad = True
if bad:
    quit(1)
