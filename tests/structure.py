# let's get all of it
import ctypes
import logging

import smallworld

smallworld.setup_logging(level=logging.INFO)
smallworld.setup_hinting(verbose=True, stream=True, file="hints.jsonl")


# note: code is of type bytes
code = smallworld.Code.from_filepath("struct.bin", base=0x1000, entry=0x1000)

# create a small world
cpu = smallworld.cpus.AMD64CPUState()
zero = smallworld.initializers.ZeroInitializer()
cpu.initialize(zero)

# Next we, look at hints and see fail at
# 2nd instruction bc
# unintialized memory being read by
# mov eax, DWORD [rdi+24]

# # so we create some memory

# memory = smallworld.Memory(where=0x2000, size=0x1000, init=smallworld.ZeroInitialize)

# sw.map(memory)

# sw.rdi = memory.start

# # we re-analyze
# sw.analyze()

# presumably this gets through the loop one iteration
# (*curr) all slots are zero.  So we set curr to curr->next which is 0x0
# so 2nd iter of loop we try to read memory @ 0x8 with
# mov     rax, QWORD [rdi+8]
# which fails.
# Anyhow, this plus other magical hints will allow us to write all of
# the following which should be enough to fully execute the loop for
# a couple of iterations

# this is an allocator in charge of a memory region that
# starts at 0x2000 and is of size 0x1000 and full of zeros.
alloc = smallworld.state.BumpAllocator(address=0x2000, size=0x1000)


# seems like ctypes is a good way to compactly express a type like `struct node` from struct.s
class StructNode(ctypes.LittleEndianStructure):
    _pack_ = 8
    _fields_ = [
        ("data", ctypes.c_int32),
        ("next", ctypes.c_int64),
        ("prev", ctypes.c_int64),
        ("empty", ctypes.c_int32),
    ]


# create two nodes with data and empty slots filled in
node1 = StructNode()
node1.data = 0  # thus ->next will get used to traverse
node1.empty = 0
node1.prev = 0
node1_addr = alloc.malloc(node1)

node2 = StructNode()
node2.data = 1  # thus ->prev wil get used to traverse
node2.empty = 0
node2_addr = alloc.malloc(node2)

# and link them up
node1.next = node2_addr
node2.prev = node1_addr

# this will point to the root of this doubly linked list
# commenting this out to make mypy happy
cpu.rdi.set(node1_addr)
print(f"RDI: {hex(cpu.rdi.get())}")
# all the allocated things get put in memory as concrete bytes
cpu.map(alloc)

smallworld.analyze(code, cpu)

# now we can do a single micro-execution without error
# final_state = smallworld.emulate(code, cpu)

# print first 64 bytes in that allocated (and now changed) memory
# to look at the result. this is gross.  Maybe we should be able to
# use that cytpes struct defn to read out memory and understand it
# print(final_state.memory(0x2000, 64))
