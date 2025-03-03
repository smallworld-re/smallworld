import logging
import typing

import smallworld

# Set up logging and hinting
smallworld.logging.setup_logging(level=logging.INFO)
smallworld.hinting.setup_hinting(stream=True, verbose=True)

# Create a machine
machine = smallworld.state.Machine()


# Load and add code into the state
code = smallworld.state.memory.code.Executable.from_elf(
    open("bin/test_input.amd64.elf", "rb"), address=0x10000000
)
machine.add(code)

# Create a CPU
cpu = smallworld.state.cpus.CPU.for_platform(code.platform)
machine.add(cpu)

# Set the instruction pointer to the target function
pc = code.get_symbol_value("bazgorp")
cpu.rip.set(pc)

# Set up input detection analysis
analyses: typing.List[
    typing.Union[smallworld.analyses.Analysis, smallworld.analyses.Filter]
] = [smallworld.analyses.InputDetection()]

smallworld.analyze(machine, analyses)
