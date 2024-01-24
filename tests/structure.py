# type: ignore
# let's get all of it
import ctypes
import logging

import smallworld.smallworld as sw
from smallworld import utils

utils.setup_logging(level=logging.INFO)
utils.setup_hinting(verbose=True, stream=True, file="hints.jsonl")

# create a small world
conf = sw.X86_64()
smw = sw.Smallworld(config=conf)

# note: code is of type bytes
code = open("struct.bin", "rb").read()

# map the code into memory at this address
smw.map_code(base=0x1000, entry=0x1000, code=code)

# analyze code given that entry point
# Ouput: this will log hints somewhere
smw.analyze()

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
alloc = sw.BumpAllocator(base_addr=0x2000, size=0x1000, config=conf)


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
node1_addr = alloc.malloc(node1)

node2 = StructNode()
node2.data = 1  # thus ->prev wil get used to traverse
node2.empty = 1
node2_addr = alloc.malloc(node2)

# and link them up
node1.next = node2_addr

# this will point to the root of this doubly linked list
# commenting this out to make mypy happy
smw.rdi = node1_addr
print(f"RDI: {hex(smw.rdi)}")
# all the allocated things get put in memory as concrete bytes
smw.map_region(alloc)

# now we can do a single micro-execution without error
final_state = smw.emulate(num_instructions=13)

# print first 64 bytes in that allocated (and now changed) memory
# to look at the result. this is gross.  Maybe we should be able to
# use that cytpes struct defn to read out memory and understand it
print(final_state.memory(0x2000, 64))
