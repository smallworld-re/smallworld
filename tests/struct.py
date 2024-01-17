
# let's get all of it
import smallworld 

sw = smallword.Smallworld(cpu=smallword.X84_64)

# code is of type bytes
code = open("struct.bin", "rb").read()

sw.map(0x1000, code)

sw.entry = 0x1000

# logs hints
sw.analyze()

# we look at hints and see fail at
# 2nd instruction bc 
# unintialized memory being read by 
# mov eax, DWORD [rdi+24]

# so we create some memory

memory = smallword.Memory(where=0x2000, size=0x1000, init=smallword.ZeroInitialize)

sw.map(memory)

sw.rdi = memory.start

# we re-analyze 
sw.analyze()

# hints tell us magically that we need to do the following

# where is start addr of memory this allocator will provide
# size is how many bytes in the region it can provide
# and init is how we intialize it
alloc = smallword.BumpAllocator(where=0x2000, size=0x1000, init=smallword.ZeroInitalize)

class StructNode (ctypes.LittleEndianStructure):

    _pack_ = 8
    _fields_ = [
        ("data", ctypes.int32),
        ("next", ctypes.uint64),
        ("prev", ctypes.uint64),
        ("empty", ctypes.int32)
    ]


node1 = StructNode()
node1.data = 0  # thus ->next will get used to traverse
node1.empty = 0
node1_addr = alloc.malloc(node1)

node2 = StructNode()
node2.data = 1  # thus ->prev wil get used to traverse
node2.empty = 1
node2_alloc = alloc.malloc(node2)

node1.next = node2_addr

sw.rdi = node1_addr


# all the allocated things get put in memory as bytes
sw.map(alloc)

# which lets us now do a single micro-execution with
final_state = sw.emulate(num_instructions=16,engine=smallword.unicorn)

# print first 64 bytes in that allocated (and now changed) memory
print(final_state.memory(0x2000, 64))



