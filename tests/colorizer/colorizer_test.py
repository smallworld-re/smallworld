import copy
import logging
import pathlib
import random
import sys

import smallworld
from smallworld import hinting
from smallworld.analyses import Colorizer, ColorizerReadWrite, ColorizerSummary
from smallworld.analyses.colorizer import randomize_uninitialized
from smallworld.hinting.hints import (
    DynamicMemoryValueSummaryHint,
    DynamicRegisterValueSummaryHint,
    TraceExecutionHint,
)
from smallworld.instructions.bsid import BSIDMemoryReferenceOperand
from smallworld.platforms.defs.platformdef import PlatformDef

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

# create an executable and add it to the machine
path = pathlib.Path(__file__).parent.resolve()
code = smallworld.state.memory.code.Executable.from_elf(
    open(f"{path}/../trace_executor/ahme-x86_64", "rb"), address=0x1000
)
machine.add(code)

# Create a stack and add it to the state
stack = smallworld.state.memory.stack.Stack.for_platform(platform, 0x10000, 0x4000)
machine.add(stack)
rsp = stack.get_pointer()
cpu.rsp.set(rsp)

entry_point = 0x2159
exit_point = 0x225A

cpu.rip.set(entry_point)
machine.add(cpu)
machine.add_exit_point(exit_point)

hints = []


def collect_hints(hint):
    hints.append(hint)


# num_micro_exec   How many micro executions.
# num_insn:       how many (max) instructions to execute from entry
# buflen:         length of buffer on heap that will be processed by fn foo @ 0x1169
# fortytwos:      ok, so the program ahme has a preference for byte value 42 on some branches
#                 if true, buffers with random bytes will have lots of 42s
# randomize_regs: if True, TraceExecution will randomize any regs not initialized
# seed:           seed for RNG
def test(num_micro_exec, num_insns, buflen, fortytwos, seed):
    global hints

    hints = []
    logger.info(
        f"\ntest: num_micro_exec={num_micro_exec} num_insns={num_insns} buflen={buflen} fortytwos={fortytwos} seed={seed}"
    )

    hinter = hinting.Hinter()
    hinter.register(TraceExecutionHint, collect_hints)
    hinter.register(DynamicMemoryValueSummaryHint, collect_hints)
    hinter.register(DynamicRegisterValueSummaryHint, collect_hints)
    crw = ColorizerReadWrite(hinter)
    analyses = [ColorizerSummary(hinter), crw]

    for i in range(num_micro_exec):
        logger.info(f"\nmicro exec number {i}")
        c = Colorizer(hinter, num_insns=num_insns, exec_id=i)

        machine_copy = copy.deepcopy(machine)
        cpu = machine_copy.get_cpus()[0]
        heap_size = 0x1000
        heap = smallworld.state.memory.heap.BumpAllocator(0x20000, heap_size)
        machine_copy.add(heap)

        random.seed(seed + i)
        bytz = random.randbytes(buflen)
        if fortytwos:
            for j in range(buflen):
                if random.random() > 0.5:
                    bytz = bytz[:j] + b"\x2a" + bytz[j + 1 :]
        for j in range(buflen):
            logger.info(f"buf[{j}] = {bytz[j]:x}")
        buf = heap.allocate_bytes(bytz, "buf")
        # arg 1 of foo is addr of buffer
        cpu.rdi.set_content(buf)
        # arg 2 is length of buffer
        cpu.esi.set_content(buflen)

        perturbed_machine = randomize_uninitialized(
            machine_copy, seed + i, ["rbp", "rsp"]
        )
        c.run(perturbed_machine)

    smallworld.analyze(perturbed_machine, analyses)

    pdef = PlatformDef.for_platform(platform)

    print("--------------------------")
    d1 = (0x221F, "rax", crw.graph.derive(0x221F, True, pdef.registers["rax"]))
    print(f"0x221f rax -- {d1}")

    print("--------------------------")
    d2 = (0x219C, "rax", crw.graph.derive(0x219C, True, pdef.registers["rax"]))
    print(f"0x219c rax -- {d2}")

    print("--------------------------")
    d3 = (0x21F0, "al", crw.graph.derive(0x21F0, True, pdef.registers["al"]))
    print(f"0x21f0 al -- {d3}")

    print("--------------------------")
    d4 = (
        0x2183,
        "[rbp-0x18]",
        crw.graph.derive(
            0x2183,
            True,
            BSIDMemoryReferenceOperand(base="rbp", index=None, scale=1, offset=-0x18),
        ),
    )
    print(f"0x2183 [rbp-0x18] -- {d4}")

    print("--------------------------")
    d5 = (
        0x216E,
        "[rbp-0x1c]",
        crw.graph.derive(
            0x216E,
            True,
            BSIDMemoryReferenceOperand(base="rbp", index=None, scale=1, offset=-0x1C),
        ),
    )
    print(f"0x216e [rbp-0x1c] -- {d5}")

    print("--------------------------")
    d6 = (
        0x2178,
        "[rbp-0x20]",
        crw.graph.derive(
            0x2178,
            True,
            BSIDMemoryReferenceOperand(base="rbp", index=None, scale=1, offset=-0x20),
        ),
    )
    print(f"0x2178 [rbp-0x20] -- {d6}")

    return ([d1, d2, d3, d4, d5, d6], hints)


if __name__ == "__main__":
    try:
        num_micro_exec = int(sys.argv[1])
        num_insns = int(sys.argv[2])
        buflen = int(sys.argv[3])
        fortytwos = sys.argv[4] == "True"
        seed = int(sys.argv[5])
    except:
        logger.info("Error in one or more args")
        logger.info(
            """Usage: colorizer_test.py num_insns buflen fortytwos seed
num_micro_exec  How many micro executions.
num_insns:       How many (max) instructions to execute from entry for each micro exec.
buflen:         Length of buffer on heap that will be processed by fn foo @ 0x1169
fortytwos:      The program handed to the colorizer for analysis, ahme, has a preference
                for byte value 42 on some branches. If true, buffers with random bytes
                will be roughly half 42s.
seed:           Seed for random number generator."""
        )
        sys.exit(1)

    _ = test(num_micro_exec, num_insns, buflen, fortytwos, seed)
