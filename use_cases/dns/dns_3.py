import logging
import pathlib

import lief
from field_analysis import FieldDetectionAnalysis
from malloc import FreeModel, MallocModel

import smallworld
import smallworld.analyses.unstable.angr.visitor

# Stage 3 DNS exploration: Play with buf.a
#
# In our last experiment, we determined buf.a
# is controlling how buf gets parsed.
#
# We know the following rules:
# - If buf.a & 0xc != 0, the routine exits
# - If buf.a == 0, the routine id's buf[0:2] as a field.
# - If buf.a > 0, the routine id's buf[0:1] as a field.
#
# Let's explore the behavior when buf[0:1] is a field.
# Here, we add the ability to track malloc'd arrays of items.
# It's limited, but I know that msg.hdr.msg.a.len
# is responsible for an array of homogenous structs
# of size 264
#

# Set up logging and hinting
smallworld.logging.setup_logging(level=logging.INFO)
smallworld.hinting.setup_hinting(stream=False, verbose=True)

log = logging.getLogger("smallworld")

# Create a machine
machine = smallworld.state.Machine()

# Load the code
filepath = pathlib.Path(__file__).parent / "bin" / "dns.amd64.bin"
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
elf = lief.parse(filepath)
sym = elf.get_static_symbol("parse_dns_message")
cpu.rip.set(code.address + sym.value)

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

malloc.bind_length_to_struct("msg.hdr.msg.a.len", "msg.a.item", [(264, "unk")])

free = FreeModel(0x1036)
machine.add(free)
machine.add_bound(free._address, free._address + 16)

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
gdata[60] = smallworld.state.EmptyValue(1, None, "buf.a")
gdata[61] = smallworld.state.EmptyValue(1, None, "buf.b")
gdata[62] = smallworld.state.EmptyValue(1, None, "buf.c")
gdata[63] = smallworld.state.EmptyValue(497, None, "buf")
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

analysis.set_extra_constraints([(1, "buf.a", "gt", 0)])
machine.analyze(analysis)
