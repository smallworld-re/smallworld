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
    smallworld.platforms.Architecture.MIPS32, smallworld.platforms.Byteorder.LITTLE
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
    code = smallworld.state.memory.code.Executable.from_elf(f, platform=platform)
    machine.add(code)
    for bound in code.bounds:
        machine.add_bound(bound[0], bound[1])

# Create a stack and add it to the state
stack = smallworld.state.memory.stack.Stack.for_platform(platform, 0x2000, 0x4000)
machine.add(stack)

# Set an exit point
cpu.ra.set_label("Return Address")

# Configure the stack pointer
sp = stack.get_pointer()
cpu.sp.set(sp)

# Set up analyses


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


def run_test(
    symbol,
    hint_type=None,
    diagnosis_type=None,
    halt_type=None,
    halt_kind=None,
    halt_target=None,
    illegal_type=None,
    mem_access=None,
):
    log.info(f"Test: {symbol}")
    cpu.pc.set(code.get_symbol_value(symbol))
    cpu.t9.set(code.get_symbol_value(symbol))

    hinter = smallworld.hinting.Hinter()
    analyses: typing.List[smallworld.analyses.Analysis] = [
        smallworld.analyses.CrashTriageVerification(
            hinter,
            max_steps=20,
            hint_type=hint_type,
            diagnosis_type=diagnosis_type,
            halt_type=halt_type,
            halt_kind=halt_kind,
            halt_target=halt_target,
            mem_access=mem_access,
        )
    ]
    try:
        smallworld.analyze(machine, analyses)
        return True
    except smallworld.exceptions.AnalysisError as e:
        log.error(f"{symbol} FAILED: {e}")
        return False


good = True

good &= run_test(
    "example_initialized_global",
)
good &= run_test(
    "example_uninitialized_global",
)

# good &= run_test("early_lost")
# good &= run_test("early_halt_deadend_bounds")
# good &= run_test("early_halt_deadend_mmap")
good &= run_test(
    "early_halt_unconstrained_call",
    diagnosis_type=smallworld.analyses.crash_triage.DiagnosisEarlyMemory,
)
# good &= run_test("early_halt_unconstrained_return")
# good &= run_test("early_halt_unconstrained_jump")
good &= run_test(
    "early_halt_diverged",
    diagnosis_type=smallworld.analyses.crash_triage.DiagnosisEarlyHalt,
    halt_type=smallworld.analyses.crash_triage.HaltDiverged,
)
# good &= run_test("early_illegal")

# good &= run_test("oob_deadend_bounds")
good &= run_test(
    "oob_deadend_mmap",
    hint_type=smallworld.analyses.crash_triage.TriageOOB,
    diagnosis_type=smallworld.analyses.crash_triage.DiagnosisOOB,
    halt_type=smallworld.analyses.crash_triage.HaltDeadended,
    halt_kind="unmapped",
    halt_target="call",
)

# NOTE: On MIPS, unconstrained exits get reported as a memory error,
# not as a code bounds error.
good &= run_test(
    "oob_unconstrained_call",
    hint_type=smallworld.analyses.crash_triage.TriageMemory,
    diagnosis_type=smallworld.analyses.crash_triage.DiagnosisMemory,
    mem_access=smallworld.analyses.crash_triage.MemoryAccess.FETCH,
)
good &= run_test(
    "oob_unconstrained_return",
    hint_type=smallworld.analyses.crash_triage.TriageMemory,
    diagnosis_type=smallworld.analyses.crash_triage.DiagnosisMemory,
    mem_access=smallworld.analyses.crash_triage.MemoryAccess.FETCH,
)
# good &= run_test("oob_unconstrained_jump")
# good &= run_test("oob_diverged")

good &= run_test(
    "illegal_undecodable",
    hint_type=smallworld.analyses.crash_triage.TriageIllegal,
    diagnosis_type=smallworld.analyses.crash_triage.DiagnosisIllegal,
    illegal_type=smallworld.analyses.crash_triage.IllegalInstrNoDecode,
)
good &= run_test(
    "illegal_decodable",
    hint_type=smallworld.analyses.crash_triage.TriageIllegal,
    diagnosis_type=smallworld.analyses.crash_triage.DiagnosisIllegal,
    illegal_type=smallworld.analyses.crash_triage.IllegalInstrUnconfirmed,
)

good &= run_test(
    "mem_read_constrained",
    hint_type=smallworld.analyses.crash_triage.TriageMemory,
    diagnosis_type=smallworld.analyses.crash_triage.DiagnosisMemory,
    mem_access=smallworld.analyses.crash_triage.MemoryAccess.READ,
)
good &= run_test(
    "mem_write_constrained",
    hint_type=smallworld.analyses.crash_triage.TriageMemory,
    diagnosis_type=smallworld.analyses.crash_triage.DiagnosisMemory,
    mem_access=smallworld.analyses.crash_triage.MemoryAccess.WRITE,
)
good &= run_test(
    "mem_read_unconstrained",
    hint_type=smallworld.analyses.crash_triage.TriageMemory,
    diagnosis_type=smallworld.analyses.crash_triage.DiagnosisMemory,
    mem_access=smallworld.analyses.crash_triage.MemoryAccess.READ,
)
good &= run_test(
    "mem_write_unconstrained",
    hint_type=smallworld.analyses.crash_triage.TriageMemory,
    diagnosis_type=smallworld.analyses.crash_triage.DiagnosisMemory,
    mem_access=smallworld.analyses.crash_triage.MemoryAccess.WRITE,
)


if not good:
    log.error("At least one analysis failed; check the logs")
    quit(1)
