"""A simple example demonstrating state storage primitives."""

import argparse
import logging

import unicorn

from smallworld import cpus, exceptions, executor, executors, initializer, utils

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

utils.setup_logging(level=level)

cpu = cpus.AMD64CPUState()
emu = executors.UnicornExecutor(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
zero = initializer.ZeroInitializer()

cpu.initialize(zero)
cpu.apply(emu)

target = executor.Code.from_filepath(arguments.target, base=0x1000)

emu.load(target)

try:
    emu.run()
except exceptions.EmulationError:
    pass

cpu.load(emu)

print("=" * 80)
print("final state:")
print(cpu.stringify(truncate=False))
