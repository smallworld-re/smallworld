import logging
import pathlib

import lief
from field_analysis import FieldDetectionAnalysis

import smallworld
import smallworld.analyses.unstable.angr.visitor

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

# Configure somewhere for arguments to live
gdata = smallworld.state.memory.Memory(0x6000, 0x1000)
machine.add(gdata)
# DNS message struct
# Sort of cheating that I know how big it is.
gdata[0] = smallworld.state.EmptyValue(48, None, "msg")
# Input buffer
gdata[48] = smallworld.state.EmptyValue(512, None, "buf")
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
