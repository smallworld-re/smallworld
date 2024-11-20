import logging
import pathlib

import lief
from field_analysis import FieldDetectionAnalysis
from malloc import MallocModel

import smallworld
import smallworld.analyses.unstable.angr.visitor

# Stage 1 DNS exploration: First Malloc
#
# I've run through the process of parsing DNS headers
# from the input buffer.
#
# This will fail on the first call to malloc(),
# since at least one of the header fields msg.hdr.c
# is getting interpreted as a length.

# Set up logging and hinting
smallworld.logging.setup_logging(level=logging.INFO)
smallworld.hinting.setup_hinting(stream=True, verbose=True)

log = logging.getLogger("smallworld")

# Define the platform
platform = smallworld.platforms.Platform(
    smallworld.platforms.Architecture.X86_64, smallworld.platforms.Byteorder.LITTLE
)

# Create a machine
machine = smallworld.state.Machine()

# Create a CPU
cpu = smallworld.state.cpus.CPU.for_platform(platform)
machine.add(cpu)

# Load and add code into the state
filepath = pathlib.Path(__file__).parent / "dns.bin"
with open(filepath, "rb") as f:
    code = smallworld.state.memory.code.Executable.from_elf(f, 0x40000)
    machine.add(code)

for bound in code.bounds:
    machine.add_bound(bound.start, bound.stop)

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
malloc = MallocModel(0x1090, heap)
machine.add(malloc)
machine.add_bound(malloc._address, malloc._address + 16)

# Configure somewhere for arguments to live
gdata = smallworld.state.memory.Memory(0x6000, 0x1000)
machine.add(gdata)

# DNS message struct
# I cheated a bit; I know it's a nested struct
gdata[0] = smallworld.state.EmptyValue(2, None, "msg.hdr.a")
gdata[2] = smallworld.state.EmptyValue(2, None, "msg.hdr.b")
gdata[4] = smallworld.state.EmptyValue(2, None, "msg.hdr.c")
gdata[6] = smallworld.state.EmptyValue(2, None, "msg.hdr.d")
gdata[8] = smallworld.state.EmptyValue(2, None, "msg.hdr.e")
gdata[10] = smallworld.state.EmptyValue(2, None, "msg.hdr.f")
# NOTE: 4 bytes of padding here; never referenced
gdata[16] = smallworld.state.EmptyValue(8, None, "msg.a")
gdata[24] = smallworld.state.EmptyValue(8, None, "msg.b")
gdata[32] = smallworld.state.EmptyValue(8, None, "msg.c")
gdata[40] = smallworld.state.EmptyValue(8, None, "msg.d")
# Input buffer
gdata[48] = smallworld.state.EmptyValue(2, None, "buf.a")
gdata[50] = smallworld.state.EmptyValue(2, None, "buf.b")
gdata[52] = smallworld.state.EmptyValue(2, None, "buf.c")
gdata[54] = smallworld.state.EmptyValue(2, None, "buf.d")
gdata[56] = smallworld.state.EmptyValue(2, None, "buf.e")
gdata[58] = smallworld.state.EmptyValue(2, None, "buf.f")
gdata[60] = smallworld.state.EmptyValue(500, None, "buf")
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

machine.analyze(FieldDetectionAnalysis(platform))
