import logging
import typing

import smallworld

# Set up logging and hinting
smallworld.logging.setup_logging(level=logging.DEBUG)
logging.getLogger("angr").setLevel(logging.WARNING)
logging.getLogger("claripy").setLevel(logging.WARNING)
logging.getLogger("pyvex").setLevel(logging.WARNING)
logging.getLogger("smallworld").setLevel(logging.INFO)
logging.getLogger("smallworld.analyses.crash_triage").setLevel(logging.DEBUG)

# Define the platform
platform = smallworld.platforms.Platform(
    smallworld.platforms.Architecture.X86_32, smallworld.platforms.Byteorder.LITTLE
)

# Create a machine
machine = smallworld.state.Machine()

# Create a CPU
cpu = smallworld.state.cpus.CPU.for_platform(platform)
machine.add(cpu)

# Load and add code into the state
filename = (
    __file__.replace(".py", ".elf")
    .replace(".angr", "")
    .replace(".panda", "")
    .replace(".pcode", "")
)
with open(filename, "rb") as f:
    code = smallworld.state.memory.code.Executable.from_elf(
        f, platform=platform, address=0x400000
    )
    machine.add(code)
    for bound in code.bounds:
        machine.add_bound(bound[0], bound[1])

# Create a stack and add it to the state
stack = smallworld.state.memory.stack.Stack.for_platform(platform, 0x2000, 0x4000)
machine.add(stack)

# Label an argument
stack.push_symbolic(4, "Arg 1")

# Label an exit point
stack.push_symbolic(4, "Return address")

# Configure the stack pointer
esp = stack.get_pointer()
cpu.esp.set(esp)

# Set up analyses
hinter = smallworld.hinting.Hinter()

printer = smallworld.analyses.CrashTriagePrinter(hinter)
printer.run(machine)

analyses: typing.List[smallworld.analyses.Analysis] = [
    smallworld.analyses.CrashTriage(hinter)
]

# Test one: out of bounds
cpu.pc.set(code.get_symbol_value("bad_jump"))
smallworld.analyze(machine, analyses)

# Test two: uninitialized function pointer
cpu.pc.set(code.get_symbol_value("bad_function_pointer"))
smallworld.analyze(machine, analyses)

# Test three: return out of context
cpu.pc.set(code.get_symbol_value("bad_return"))
smallworld.analyze(machine, analyses)

# Test four: branch on uninitialized
cpu.pc.set(code.get_symbol_value("bad_if"))
smallworld.analyze(machine, analyses)

# Test five: Illegal instruction
cpu.pc.set(code.get_symbol_value("bad_instruction"))
smallworld.analyze(machine, analyses)
