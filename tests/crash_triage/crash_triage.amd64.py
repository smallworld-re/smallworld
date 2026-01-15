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

log = logging.getLogger(__name__)

# Define the platform
platform = smallworld.platforms.Platform(
    smallworld.platforms.Architecture.X86_64, smallworld.platforms.Byteorder.LITTLE
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

# Set an exit point
stack.push_symbolic(8, "Return address")

# Configure the stack pointer
rsp = stack.get_pointer()
cpu.rsp.set(rsp)

# Set up analyses
hinter = smallworld.hinting.Hinter()
analyses: typing.List[smallworld.analyses.Analysis] = [
    smallworld.analyses.CrashTriage(hinter)
]


printer = smallworld.analyses.CrashTriagePrinter(hinter)
printer.run(machine)

# Need to test:
# - Early:
#   - Lost trace (difficult)
#   - Halted:
#       - Deadended:
#           - Bounds (difficult)
#           - Memory map (difficult)
#       - Unconstrained:
#           - Call
#           - Return (difficult)
#           - Jump (difficult)
#       - Diverged
#   - Illegal (difficult on this ISA)
# - OOB:
#   - Deadended:
#       - Out of bounds
#       - Unmapped
#   - Unconstrained:
#       - Call
#       - Return
#       - Branch (difficult)
# - Illegal:
#   - Undecodable
#   - Confirmed
#   - Unconfirmed
# - Memory:


def run_test(symbol):
    log.info(f"Test: {symbol}")
    cpu.rip.set(code.get_symbol_value(symbol))
    smallworld.analyze(machine, analyses)


# run_test("early_lost")
# run_test("early_halt_deadend_bounds")
# run_test("early_halt_deadend_mmap")
run_test("early_halt_unconstrained_call")
# run_test("early_halt_unconstrained_return")
# run_test("early_halt_unconstrained_jump")
run_test("early_halt_diverged")
# run_test("early_illegal")


# run_test("oob_deadend_bounds")
run_test("oob_deadend_mmap")
run_test("oob_unconstrained_call")
run_test("oob_unconstrained_return")
run_test("oob_unconstrained_jump")
# run_test("oob_diverged")

quit()

run_test("illegal_undecodable")
run_test("illegal_decodable")

run_test("mem_read_constrained")
run_test("mem_read_unconstrained")
run_test("mem_write_constrained")
run_test("mem_write_unconstrained")
