"""A simple example demonstrating state storage primitives."""

import argparse
import logging

import smallworld

parser = argparse.ArgumentParser(
    description="run a simple shellcode example in unicorn"
)

parser.add_argument("target", help="shellcode file to execute")

parser.add_argument(
    "-v", "--verbose", action="store_true", help="enable verbose logging"
)

arguments = parser.parse_args()

if arguments.verbose:
    level = logging.DEBUG
else:
    level = logging.INFO

smallworld.setup_logging(level=level)

cpu = smallworld.cpus.AMD64CPUState()
emu = smallworld.emulators.UnicornEmulator("x86", "64")
zero = smallworld.initializers.ZeroInitializer()

cpu.initialize(zero)
cpu.apply(emu)

target = smallworld.emulators.Code.from_filepath(arguments.target, base=0x1000)

emu.load(target)

try:
    emu.run()
except smallworld.exceptions.EmulationError:
    pass

cpu.load(emu)

print("=" * 80)
print("final state:")
print(cpu.stringify(truncate=False))
