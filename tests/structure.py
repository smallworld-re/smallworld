# let's get all of it
import smallworld

# create a small world
sw = smallworld.Smallworld(cpu=smallworld.X84_64)

# note: code is of type bytes
code = open("struct.bin", "rb").read()

# map the code into memory at this address
sw.map(0x1000, code)

# indicate entry point
sw.entry = 0x1000

# analyze code given that entry point
# Ouput: this will log hints somewhere
sw.analyze()

# Next we, look at hints and see fail at
# 2nd instruction bc
# unintialized memory being read by
# mov eax, DWORD [rdi+24]

# so we create some memory

memory = smallworld.Memory(where=0x2000, size=0x1000, init=smallworld.ZeroInitialize)

sw.map(memory)

sw.rdi = memory.start

# we re-analyze
sw.analyze()

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
alloc = smallworld.BumpAllocator(
    where=0x2000, size=0x1000, init=smallworld.ZeroInitalize
)


# seems like ctypes is a good way to compactly express a type like `struct node` from struct.s
class StructNode(ctypes.LittleEndianStructure):
    _pack_ = 8
    _fields_ = [
        ("data", ctypes.int32),
        ("next", ctypes.uint64),
        ("prev", ctypes.uint64),
        ("empty", ctypes.int32),
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
sw.rdi = node1_addr

# all the allocated things get put in memory as concrete bytes
sw.map(alloc)

# now we can do a single micro-execution without error
final_state = sw.emulate(num_instructions=16, engine=smallworld.unicorn)

# print first 64 bytes in that allocated (and now changed) memory
# to look at the result. this is gross.  Maybe we should be able to
# use that cytpes struct defn to read out memory and understand it
print(final_state.memory(0x2000, 64))
