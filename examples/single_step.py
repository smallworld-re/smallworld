"""A simple example demonstrating state storage primitives."""

import argparse
import logging

from smallworld import cpus, executor, executors, initializer, utils

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
emu = executors.UnicornExecutor("x86", "64")
zero = initializer.ZeroInitializer()

cpu.initialize(zero)

# load/apply the cpu state into the executor
cpu.apply(emu)

target = executor.Code.from_filepath(arguments.target, base=0x1000)

emu.load(target)

done = False

while not done:
    done = emu.step()
    # load/apply the executor state into the cpu
    cpu.load(emu)

    print("=" * 80)
    print("state:")
    print(cpu.stringify(truncate=False))
