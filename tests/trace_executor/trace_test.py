import copy
import logging
import pathlib
import random
import sys

import smallworld
from smallworld import hinting
from smallworld.analyses import TraceExecution
from smallworld.hinting.hints import TraceExecutionHint

# setup logging
smallworld.logging.setup_logging(level=logging.DEBUG)

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
entry_point = 0x2189
exit_point = 0x2291

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


def check_pcs(pcs1, pcs2, label1, label2):
    if pcs1 != pcs2:
        print(f"{label1:12} pcs: {[hex(pc) for pc in pcs1]}")
        print(f"{label2:12} pcs: {[hex(pc) for pc in pcs2]}")
        ml = max(len(pcs1), len(pcs2))
        for i in range(ml):
            (pc1, pc2) = (None, None)
            if i < len(pcs1):
                pc1 = pcs1[i]
            if i < len(pcs2):
                pc2 = pcs2[i]
            assert not (pc1 is None and pc2 is None)
            if pc1 is None or pc2 is None:
                if pc1 is None:
                    print(f"     {'???':6} {pc2:6x}")
                if pc2 is None:
                    print(f"     {pc1:6x} {'???':6}")
            else:
                if pc1 == pc2:
                    print(f"     {pc1:6x} {pc2:6x}")
                if pc1 != pc2:
                    print(f" XX  {pc1:6x} {pc2:6x}")
        print(f"{label1} DOES NOT matches {label2}")
        return False

    print(f"{label1} matches {label2}")
    return True


def check_cmpinfo(hints, truth_pcs):
    pass


hints = []


def collect_hints(hint):
    global hints
    hints.append(hint)


import hashlib


def get_md5_of_bytz(bytz):
    md5_hash = hashlib.md5(bytz)
    return md5_hash.hexdigest()


print(
    hashlib.md5("000005fab4534d05key9a055eb014e4e5d52write".encode("utf-8")).hexdigest()
)


def test(num_insn, buflen, create_heap, fortytwos, randomize_regs, seed):
    global hints
    global machine

    machine_copy = copy.deepcopy(machine)
    cpu = machine_copy.get_cpus()[0]

    hints = []
    print(
        f"\ntest: num_insn={num_insn} buflen={buflen} fortytwos={fortytwos} seed={seed}"
    )
    if create_heap:
        heap_size = 0x1000
        heap = smallworld.state.memory.heap.BumpAllocator(0x20000, heap_size)
        machine_copy.add(heap)
        # we'll only create buf and set rdi to point to it if told to
        # create a heap
        random.seed(seed)
        bytz = random.randbytes(buflen)
        print(f"md5sum(bytz) = {get_md5_of_bytz(bytz)}")
        if fortytwos:
            for i in range(buflen):
                if random.random() > 0.5:
                    bytz = bytz[: i - 1] + b"\x2a" + bytz[i + 1 :]
        print("bytz:")
        for b in bytz:
            print(f"{b:x} ", end="")
        print("")
        buf = heap.allocate_bytes(bytz, "buf")
        # arg 1 of foo is addr of buffer
        cpu.rdi.set_content(buf)
    # arg 2 is length of buffer
    cpu.esi.set_content(buflen)
    cpu.rdx.set_content(0)
    hinter = hinting.Hinter()
    hinter.register(TraceExecutionHint, collect_hints)
    traceA = TraceExecution(
        hinter, num_insns=num_insn, randomize_regs=randomize_regs, seed=seed
    )
    traceA.run(machine_copy)
    return hints


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

    hints = test(num_insn, buflen, create_heap, fortytwos, randomize_regs, seed)
    print(hints)
    for te in hints[0].trace:
        print(f"pc={te.pc:x}")
