import logging
import smallworld
import ctypes
smallworld.logging.setup_logging(level=logging.INFO)

machine = smallworld.state.Machine()
code = smallworld.state.memory.code.Executable.from_filepath("struct.amd64.bin", address=0x1000)

platform = smallworld.platforms.Platform(smallworld.platforms.Architecture.X86_64, smallworld.platforms.Byteorder.LITTLE)
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

# machine.apply(emulator)
# while True:
#     try:
#         emulator.step()
#     except smallworld.exceptions.EmulationBounds:
#         print("emulation complete; encountered exit point or went out of bounds")
#         break
#     except Exception as e:
#         print(f"emulation ended; raised exception {e}")
#         break
final_machine = machine.emulate(emulator)
final_cpu = final_machine.get_cpu()

print(f"curr = {hex(final_cpu.rdi.get())}")
print(f"arg2 = {final_cpu.esi.get()}")
