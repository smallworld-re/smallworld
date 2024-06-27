import ctypes
import logging

import smallworld

smallworld.setup_logging(level=logging.INFO)
smallworld.setup_hinting(verbose=True, stream=True, file=None)

# create a small world
state = smallworld.state.CPU.for_arch("x86", "64", "little")

code = smallworld.state.Code.from_filepath(
    "struct.amd64.bin", arch="x86", mode="64", format="blob", base=0x1000, entry=0x1000
)
state.map(code)
state.rip.value = code.entry


class StructNode(ctypes.LittleEndianStructure):
    _pack_ = 8


StructNode._fields_ = [
    ("data", ctypes.c_int32),
    ("padding_0x4", ctypes.c_int32),
    ("next", smallworld.ctypes.typed_pointer(StructNode)),
    ("prev", smallworld.ctypes.typed_pointer(StructNode)),
    ("empty", ctypes.c_int32),
]

heap = smallworld.state.BumpAllocator(0x4000, 0x4000)

node_a = StructNode()
node_a.data = 2
node_a.empty = 0
node_a.prev = 0
node_a_addr = heap.malloc(node_a)

node_b = StructNode()
node_b.data = 1
node_b.empty = 1
node_b.next = 0
node_b_addr = heap.malloc(node_b)

node_a.next = node_b_addr
node_b.prev = node_a_addr

state.map(heap)

state.rdi.value = node_a_addr
state.rsi.value = 42

emulator = smallworld.emulators.UnicornEmulator(
    arch=state.arch, mode=state.mode, byteorder=state.byteorder
)
final_state = emulator.emulate(state)
print(f"curr = {hex(final_state.rdi.value)}")
print(f"arg2 = {final_state.esi.value}")

struct_off = final_state.rdi.value - heap.address
if struct_off >= 0 and struct_off < heap.size - 4:
    data = int.from_bytes(
        final_state.bumpallocator.value[struct_off : struct_off + 4],
        byteorder=state.byteorder,
    )
    print(f"curr.data = {data}")
else:
    print("rdi out of bounds")
