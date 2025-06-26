import logging

import smallworld

# Set up logging and hinting
smallworld.logging.setup_logging(level=logging.INFO)
smallworld.hinting.setup_hinting(stream=True, verbose=True)

# Define the platform
# NOTE: The core dump doesn't include the ABI flags.
platform = smallworld.platforms.Platform(
    smallworld.platforms.Architecture.ARM_V7A, smallworld.platforms.Byteorder.LITTLE
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
for line in lines:
    if line == "":
        continue
    reg, val_str = line.split(" ", maxsplit=1)
    val_str = val_str.strip()
    val_str = val_str.split(" ", maxsplit=1)[0]
    if val_str.startswith("0x"):
        val = int(val_str, 16)
        expected_regs[reg] = val


bad = False
for reg, value in code.prstatus._registers.items():
    if reg not in expected_regs:
        print(f"ERROR: {reg} was not in the register dump from GDB")
    if value != expected_regs[reg]:
        print(f"ERROR: {reg} expected: {hex(expected_regs[reg])}, actual: {hex(value)}")
        bad = True
    cpu_val = getattr(cpu, reg).get()
    if value != getattr(cpu, reg).get():
        print(f"ERROR: CPU had wrong value for {reg}: {cpu_val}")
        bad = True
if bad:
    quit(1)
