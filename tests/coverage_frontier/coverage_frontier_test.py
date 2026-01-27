import copy
import logging
import pathlib
import random
import sys

import smallworld
from smallworld import hinting
from smallworld.analyses import (  # Colorizer, ColorizerReadWrite, ColorizerSummary
    CoverageFrontier,
    TraceExecution,
)
from smallworld.hinting.hints import CoverageFrontierHint

# setup logging and hinting
smallworld.logging.setup_logging(level=logging.DEBUG)

logger = logging.getLogger(__name__)

# configure the platform for emulation
platform = smallworld.platforms.Platform(
    smallworld.platforms.Architecture.X86_64, smallworld.platforms.Byteorder.LITTLE
)

# create a machine
machine = smallworld.state.Machine()

# create a CPU and add it to the machine
cpu = smallworld.state.cpus.CPU.for_platform(platform)

path = pathlib.Path(__file__).parent.resolve()
code = smallworld.state.memory.code.Executable.from_elf(
    open(f"{path}/cf", "rb"), address=0x000
)
machine.add(code)

# Create a stack and add it to the state
stack = smallworld.state.memory.stack.Stack.for_platform(platform, 0x10000, 0x4000)
machine.add(stack)
rsp = stack.get_pointer()
cpu.rsp.set(rsp)

entry_point = 0x1149
exit_point = 0x1167

cpu.rip.set(entry_point)
machine.add(cpu)
machine.add_exit_point(exit_point)

hints = []


def collect_hints(hint):
    hints.append(hint)


# num_micro_exec   How many micro executions.
# num_insn:        how many (max) instructions to execute from entry
# seed:            seed for RNG
def test(num_micro_exec, num_insns, seed):
    global hints

    hints = []

    hinter = hinting.Hinter()
    hinter.register(CoverageFrontierHint, collect_hints)
    cf = CoverageFrontier(hinter)

    for i in range(num_micro_exec):
        logger.info(f"\nmicro exec number {i}")
        random.seed(seed + i)
        te = TraceExecution(hinter, num_insns=num_insns, seed=seed + i)
        machine_copy = copy.deepcopy(machine)
        cpu = machine_copy.get_cpus()[0]
        # choose random value for the input to this function
        cpu.rdi.set_content(random.randint(0, 0xFFFFFF))
        te.run(machine_copy)

    # NB: covg frontier `run` method doesnt actually use the machine input
    # it just works from TraceExecution hints.
    cf.run(machine)

    h = hints[0]

    e = {}
    for from_pc, to_pc_list in h.edges:
        e[from_pc] = to_pc_list
        print(f"0x{from_pc:x}", end="")
        if from_pc in h.branches:
            print(" [branch] ", end="")
        print(" -> [", end="")
        for to_pc in to_pc_list:
            print(f" 0x{to_pc_list[0]:x}", end="")
        print("]")

    print(
        f"Coverage frontier for {h.num_traces} traces contains {len(h.coverage_frontier)} branches"
    )
    for pc in h.coverage_frontier:
        assert pc in e
        assert len(e[pc]) == 1
        print(f"  half-covered branch @ 0x{pc:x}")

    return hints


if __name__ == "__main__":
    try:
        num_micro_exec = int(sys.argv[1])
        num_insns = int(sys.argv[2])
        seed = int(sys.argv[3])
    except:
        logger.info("Error in one or more args")
        logger.info(
            """Usage: colorizer_test.py num_insns buflen fortytwos seed
num_micro_exec  How many micro executions.
num_insns:       How many (max) instructions to execute from entry for each micro exec.
seed:           Seed for random number generator."""
        )
        sys.exit(1)

    _ = test(num_micro_exec, num_insns, seed)
