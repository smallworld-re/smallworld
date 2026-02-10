import logging
import pathlib

import smallworld
import smallworld.analyses.field_detection
import smallworld.analyses.unstable.angr.visitor
from smallworld.analyses.field_detection import FieldDetectionAnalysis

# Stage 0 DNS exploration: Raw buffers
#
# This gives a basic harness for the DNS example,
# setting up opaque global memory regions
# for the three arguments to parse_dns_message:
#
# - input buffer
# - message struct
# - offset
#
# This will immediately run into partial access errors

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

# Configure somewhere for arguments to live
gdata = smallworld.state.memory.Memory(0x6000, 0x1000)
machine.add(gdata)
# DNS message struct
# Sort of cheating that I know how big it is.
gdata[0] = smallworld.state.SymbolicValue(48, None, None, "msg")
# Input buffer
gdata[48] = smallworld.state.SymbolicValue(512, None, None, "buf")
# Offset into buffer
gdata[560] = smallworld.state.IntegerValue(0, 8, "off", code.platform.byteorder, False)

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
