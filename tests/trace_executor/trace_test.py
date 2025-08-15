import logging
import pathlib
import random
import sys

import smallworld
from smallworld.analyses import TraceExecution
from smallworld import hinting

# setup logging
smallworld.logging.setup_logging(level=logging.INFO)

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
    open(f"{path}/ahme-x86_64.bin", "rb"), address=0x1000
)
machine.add(code)

# Create a stack and add it to the state
stack = smallworld.state.memory.stack.Stack.for_platform(platform, 0x10000, 0x4000)
machine.add(stack)
rsp = stack.get_pointer()
cpu.rsp.set(rsp)

# set the instruction pointer to the entrypoint of our executable
# these values are from
# % md5sum ahme-x86_64.bin
# ffe4930bb1bb00b720dc725b3c1edbf6  ahme-x86_64.bin
entry_point = 0x2169
exit_point = 0x2260

cpu.rip.set(entry_point)
machine.add(cpu)
machine.add_exit_point(exit_point)


# num_insns:      how many (max) instructions to execute from entry
# buflen:         length of buffer on heap that will be processed by fn foo @ 0x1169
# create_heap:    program needs a buffer on heap so if this is NOT true, there should be a
#                 memory unavailable error
# fortytwos:      ok, so the program ahme has a preference for byte value 42 on some branches
#                 if true, buffers with random bytes will have lots of 42s
# randomize_regs: if True, TraceExecution will randomize any regs not initialized
# seed:           seed for RNG

num_calls = 0


def test(num_insn, buflen, create_heap, fortytwos, randomize_regs, seed):
    global num_calls

    print(
        f"\ntest: num_insn={num_insn} buflen={buflen} fortytwos={fortytwos} seed={seed}"
    )
    if create_heap:
        heap_size = 0x1000
        heap = smallworld.state.memory.heap.BumpAllocator(0x20000, heap_size)
        machine.add(heap)
        # we'll only create buf and set rdi to point to it if told to
        # create a heap
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
    hinter = hinting.Hinter()
    traceA = TraceExecution(
        hinter, num_insns=num_insn, randomize_regs=randomize_regs, seed=seed + num_calls
    )
    traceA.run(machine)
    num_calls += 1


if __name__ == "__main__":
    try:
        num_insn = int(sys.argv[1])
        buflen = int(sys.argv[2])
        create_heap = sys.argv[3] == "True"
        fortytwos = sys.argv[4] == "True"
        randomize_regs = sys.argv[5] == "True"
        seed = int(sys.argv[6])
    except:
        print("Error in one or more args")
        print(
            """Usage: trace_test.py insn buflen create_heap fortytwos randomize_regs seed
num_insn:       How many (max) instructions to execute from entry for each micro exec.
buflen:         Length of buffer on heap that will be processed by fn foo @ 0x1169
create_heap:    program needs a buffer on heap so if this is NOT true, there should be a
                memory unavailable error
fortytwos:      The program handed to the colorizer for analysis, ahme, has a preference
                for byte value 42 on some branches. If true, buffers with random bytes
                will be roughly half 42s.
randomize_regs: if True, TraceExecution will randomize any regs not initialized
seed:           Seed for random number generator."""
        )
        sys.exit(1)

    test(num_insn, buflen, create_heap, fortytwos, randomize_regs, seed)
