"""A simple example demonstrating state storage primitives."""

import logging
import argparse

from smallworld import cpus
from smallworld import executors
from smallworld import executable
from smallworld import initializer
from smallworld import exceptions
from smallworld import utils

import unicorn


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
executor = executors.UnicornExecutor(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
zero = initializer.ZeroInitializer()

cpu.initialize(zero)
cpu.apply(executor)

target = executable.Executable.from_filepath(arguments.target, base=0x1000)

executor.load(target)

try:
    executor.run()
except exceptions.EmulationError:
    pass

cpu.load(executor)

print("=" * 80)
print("final state:")
print(cpu.stringify(truncate=False))
