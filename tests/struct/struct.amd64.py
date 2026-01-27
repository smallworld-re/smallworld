import ctypes
import logging

import smallworld

smallworld.logging.setup_logging(level=logging.INFO)

machine = smallworld.state.Machine()
code = smallworld.state.memory.code.Executable.from_filepath(
    __file__.replace(".py", ".bin").replace(".angr", "").replace(".panda", ""),
    address=0x1000,
)

platform = smallworld.platforms.Platform(
    smallworld.platforms.Architecture.X86_64, smallworld.platforms.Byteorder.LITTLE
)
cpu = smallworld.state.cpus.CPU.for_platform(platform)


class StructNode(ctypes.LittleEndianStructure):
    _pack_ = 8


StructNode._fields_ = [
    ("data", ctypes.c_int32),
    ("padding_0x4", ctypes.c_int32),
    ("next", smallworld.extern.ctypes.create_typed_pointer(StructNode)),
    ("prev", smallworld.extern.ctypes.create_typed_pointer(StructNode)),
    ("empty", ctypes.c_int32),
]

heap = smallworld.state.memory.heap.BumpAllocator(0x4000, 0x4000)

node_a = StructNode()
node_a.data = 2
node_a.empty = 0
node_a.prev = 0
node_a_addr = heap.allocate(smallworld.state.Value.from_ctypes(node_a, "node a"))

node_b = StructNode()
node_b.data = 1
node_b.empty = 1
node_b.next = 0
node_b_addr = heap.allocate(smallworld.state.Value.from_ctypes(node_b, "node b"))

node_a.next = node_b_addr
node_b.prev = node_a_addr

machine.add(heap)
machine.add(cpu)
machine.add(code)

cpu.rip.set(0x1000)
cpu.rdi.set_content(node_a_addr)
cpu.rsi.set_content(42)
emulator = smallworld.emulators.UnicornEmulator(platform)
emulator.add_exit_point(cpu.rip.get() + 26)

*_, final_machine = machine.step(emulator)

final_cpu = final_machine.get_cpu()
print(f"curr = {hex(final_cpu.rdi.get())}")

heap.extract(emulator)
final_node_b_bytes = heap.read_bytes(node_b_addr, ctypes.sizeof(StructNode))
final_node_b = StructNode.from_buffer_copy(final_node_b_bytes)
print(f"node_b->data = {final_node_b.data}")
