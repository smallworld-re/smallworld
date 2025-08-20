import logging
import pathlib

import smallworld
import smallworld.analyses.field_detection
import smallworld.analyses.unstable.angr.visitor
from smallworld.analyses.field_detection import FieldDetectionAnalysis

# Set up logging and hinting
smallworld.logging.setup_logging(level=logging.INFO)

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
    machine.add_bound(bound[0], bound[1])

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

# Configure somewhere for arguments to live
gdata = smallworld.state.memory.Memory(0x6000, 0x1000)
machine.add(gdata)

# DNS message struct
# I cheated a bit; I know it's a nested struct
gdata[0] = smallworld.state.SymbolicValue(2, None, None, "msg.hdr.a")
gdata[2] = smallworld.state.SymbolicValue(2, None, None, "msg.hdr.b")
gdata[4] = smallworld.state.SymbolicValue(2, None, None, "msg.hdr.c")
gdata[6] = smallworld.state.SymbolicValue(2, None, None, "msg.hdr.d")
gdata[8] = smallworld.state.SymbolicValue(2, None, None, "msg.hdr.e")
gdata[10] = smallworld.state.SymbolicValue(2, None, None, "msg.hdr.f")
# NOTE: 4 bytes of padding here; never referenced
gdata[16] = smallworld.state.SymbolicValue(8, None, None, "msg.a")
gdata[24] = smallworld.state.SymbolicValue(8, None, None, "msg.b")
gdata[32] = smallworld.state.SymbolicValue(8, None, None, "msg.c")
gdata[40] = smallworld.state.SymbolicValue(8, None, None, "msg.d")
# Input buffer
gdata[48] = smallworld.state.SymbolicValue(2, None, None, "buf.a")
gdata[50] = smallworld.state.SymbolicValue(2, None, None, "buf.b")
gdata[52] = smallworld.state.SymbolicValue(2, None, None, "buf.c")
gdata[54] = smallworld.state.SymbolicValue(2, None, None, "buf.d")
gdata[56] = smallworld.state.SymbolicValue(2, None, None, "buf.e")
gdata[58] = smallworld.state.SymbolicValue(2, None, None, "buf.f")
gdata[60] = smallworld.state.SymbolicValue(500, None, None, "buf")
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
