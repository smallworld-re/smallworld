import logging
import pathlib

from field_analysis import FieldDetectionAnalysis
from malloc import FreeModel, MallocModel

import smallworld
import smallworld.analyses.unstable.angr.visitor

# Stage 5 DNS exploration: Complete msg.a.item
#
# This harness contains a complete description
# of msg.a's items, and their representation
# on the wire.


# Set up logging and hinting
smallworld.logging.setup_logging(level=logging.INFO)
smallworld.hinting.setup_hinting(stream=False, verbose=True)

log = logging.getLogger("smallworld")

# Create a machine
machine = smallworld.state.Machine()

# Load the code
filepath = pathlib.Path(__file__).parent / "bin" / "dns.amd64.elf"
with open(filepath, "rb") as f:
    code = smallworld.state.memory.code.Executable.from_elf(f, 0x40000)
    machine.add(code)

# Apply the code's bounds to the machine
for bound in code.bounds:
    machine.add_bound(bound.start, bound.stop)

# Use the ELF's notion of the platform
platform = code.platform

# Create the analysis; we'll need it later.
analysis = FieldDetectionAnalysis(platform)

# Create a CPU
cpu = smallworld.state.cpus.CPU.for_platform(platform)
machine.add(cpu)

# Use lief to find the address of parse_dns_message
sym = code.get_symbol_value("parse_dns_message")
cpu.rip.set(sym)

# Add a blank stack
stack = smallworld.state.memory.stack.Stack.for_platform(
    platform, 0x7FFFFFFFC000, 0x4000
)
machine.add(stack)

stack.push_integer(0x01010101, 8, None)

# Configure the stack pointer
sp = stack.get_pointer()
cpu.rsp.set(sp)

# Add a blank heap
heap = smallworld.state.memory.heap.BumpAllocator(0x20000, 0x10000)
machine.add(heap)

# Configure malloc and free models
malloc = MallocModel(
    0x1076, heap, platform, analysis.mem_read_hook, analysis.mem_write_hook
)
machine.add(malloc)
machine.add_bound(malloc._address, malloc._address + 16)

free = FreeModel(0x1036)
machine.add(free)
machine.add_bound(free._address, free._address + 16)

# Define struct msg.a.item
# This will get applied when an array is called using msg.hdr.msg.a.len
# to compute its length
#
# NOTE: The full definition would need msg.a.item.text.{i} for all i 0 - 255.
# That makes the field listing unreasonably verbose.
fields = [(1, f"text.{i}") for i in range(0, 3)]
fields.append((253, "text"))
fields.append((4, "a"))
fields.append((4, "b"))

malloc.bind_length_to_struct("msg.hdr.msg.a.len", "msg.a.item", fields)

# Configure somewhere for arguments to live
gdata = smallworld.state.memory.Memory(0x6000, 0x1000)
machine.add(gdata)

# DNS message struct
# I cheated a bit; I know it's a nested struct
gdata[0] = smallworld.state.EmptyValue(2, None, "msg.hdr.a")
gdata[2] = smallworld.state.EmptyValue(2, None, "msg.hdr.b")
gdata[4] = smallworld.state.EmptyValue(2, None, "msg.hdr.msg.a.len")
gdata[6] = smallworld.state.EmptyValue(2, None, "msg.hdr.d")
gdata[8] = smallworld.state.EmptyValue(2, None, "msg.hdr.e")
gdata[10] = smallworld.state.EmptyValue(2, None, "msg.hdr.f")
# NOTE: 4 bytes of padding here; never referenced
gdata[16] = smallworld.state.EmptyValue(8, None, "msg.a")
gdata[24] = smallworld.state.EmptyValue(8, None, "msg.b")
gdata[32] = smallworld.state.EmptyValue(8, None, "msg.c")
gdata[40] = smallworld.state.EmptyValue(8, None, "msg.d")
# Input buffer
gdata[48] = smallworld.state.EmptyValue(2, None, "buf.msg.hdr.a")
gdata[50] = smallworld.state.EmptyValue(2, None, "buf.msg.hdr.b")
# NOTE: msg.a.len is interpreted as big-endian
gdata[52] = smallworld.state.BytesValue(b"\x00\x01", "buf.msg.a.len")
gdata[54] = smallworld.state.EmptyValue(2, None, "buf.msg.hdr.d")
gdata[56] = smallworld.state.EmptyValue(2, None, "buf.msg.hdr.e")
gdata[58] = smallworld.state.EmptyValue(2, None, "buf.msg.hdr.f")
# This is a sequence of zero or more run-length-encoded strings.
# Strings can be of length 0 - 63,
# and the total number of characters can't exceed 25
gdata[60] = smallworld.state.IntegerValue(2, 1, "buf.a.item.0.text.0.len")
gdata[61] = smallworld.state.EmptyValue(1, None, "buf.a.item.0.text.0.0")
gdata[62] = smallworld.state.EmptyValue(1, None, "buf.a.item.0.text.0.1")
gdata[63] = smallworld.state.IntegerValue(0, 1, "buf.a.item.0.text.1.len")
gdata[64] = smallworld.state.EmptyValue(2, None, "buf.a.item.0.a")
gdata[66] = smallworld.state.EmptyValue(2, None, "buf.a.item.0.b")
gdata[68] = smallworld.state.EmptyValue(492, None, "buf")
# Offset into buffer
gdata[560] = smallworld.state.IntegerValue(0, 8, "off", False)

# Configure arguments
# arg 0: pointer to buf
cpu.rdi.set(gdata.address + 48)
cpu.rdi.set_label("PTR buf")
# arg 1: buffer capacity
cpu.rsi.set(512)
cpu.rsi.set_label("cap")
# arg 2: pointer to off
cpu.rdx.set(gdata.address + 560)
cpu.rdx.set_label("PTR off")
# arg 3: pointer to msg
cpu.rcx.set(gdata.address)
cpu.rcx.set_label("PTR msg")

machine.analyze(analysis)
