import logging
import pathlib
import random
import sys
import typing

import smallworld
from smallworld.analyses import Colorizer, ColorizerDefUse, ColorizerSummary

# setup logging and hinting
smallworld.logging.setup_logging(level=logging.INFO)
smallworld.hinting.setup_hinting(level=logging.DEBUG)

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
    open(f"{path}/../trace_executor/ahme-x86_64.bin", "rb"), address=0x000
)
machine.add(code)

# Create a stack and add it to the state
stack = smallworld.state.memory.stack.Stack.for_platform(platform, 0x2000, 0x4000)
machine.add(stack)
rsp = stack.get_pointer()
cpu.rsp.set(rsp)

# set the instruction pointer to the entrypoint of our executable
# these values are from
# % md5sum ahme-x86_64.bin
# ffe4930bb1bb00b720dc725b3c1edbf6  ahme-x86_64.bin
entry_point = 0x1169
exit_point = 0x1260

cpu.rip.set(entry_point)
machine.add(cpu)
machine.add_exit_point(exit_point)

heap_size = 0x1000
heap = smallworld.state.memory.heap.BumpAllocator(0x10000, heap_size)
machine.add(heap)

total_alloc = 0


# num_micro_exec   How many micro executions.
# num_insn:       how many (max) instructions to execute from entry
# buflen:         length of buffer on heap that will be processed by fn foo @ 0x1169
# fortytwos:      ok, so the program ahme has a preference for byte value 42 on some branches
#                 if true, buffers with random bytes will have lots of 42s
# randomize_regs: if True, TraceExecution will randomize any regs not initialized
# seed:           seed for RNG
def test(num_micro_exec, num_insn, buflen, fortytwos, seed):
    global total_alloc, heap_size

    print(
        f"\ntest: num_micro_exec={num_micro_exec} num_insn={num_insn} buflen={buflen} fortytwos={fortytwos} seed={seed}"
    )

    total_alloc += buflen
    assert total_alloc < heap_size

    random.seed(seed)
    bytz = random.randbytes(buflen)
    if fortytwos:
        for i in range(buflen):
            if random.random() > 0.5:
                bytz = bytz[: i - 1] + b"\x2a" + bytz[i + 1 :]
    buf = heap.allocate_bytes(bytz, "buf")
    # arg 1 of foo is addr of buffer
    cpu.rdi.set_content(buf)
    # arg 2 is length of buffer
    cpu.esi.set_content(buflen)

    analyses: typing.List[
        typing.Union[smallworld.analyses.Analysis, smallworld.analyses.Filter]
    ] = [
        Colorizer(num_micro_executions=num_micro_exec, num_insns=num_insn, seed=seed),
        ColorizerSummary(),
        ColorizerDefUse(),
    ]

    # analyze
    smallworld.analyze(machine, analyses)


if __name__ == "__main__":
    try:
        num_micro_exec = int(sys.argv[1])
        num_insn = int(sys.argv[2])
        buflen = int(sys.argv[3])
        fortytwos = sys.argv[4] == "True"
        seed = int(sys.argv[5])
    except:
        print("Error in one or more args")
        print(
            """Usage: colorizer_test.py num_insn buflen fortytwos seed
num_micro_exec  How many micro executions.
num_insn:       How many (max) instructions to execute from entry for each micro exec.
buflen:         Length of buffer on heap that will be processed by fn foo @ 0x1169
fortytwos:      The program handed to the colorizer for analysis, ahme, has a preference
                for byte value 42 on some branches. If true, buffers with random bytes
                will be roughly half 42s.
seed:           Seed for random number generator."""
        )
        sys.exit(1)

    test(num_micro_exec, num_insn, buflen, fortytwos, seed)
