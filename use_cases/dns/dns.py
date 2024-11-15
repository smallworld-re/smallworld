import logging

import lief

import smallworld
import smallworld.analyses.unstable.angr.visitor

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
filename = __file__.replace(".py", ".bin")
with open(filename, "rb") as f:
    code = smallworld.state.memory.code.Executable.from_elf(f, 0x40000)
    machine.add(code)

# Use lief to find the address of parse_dns_message
elf = lief.parse(filename)
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

# Set up the emulator
emulator = smallworld.emulators.AngrEmulator(platform)
emulator.enable_linear()

for bound in code.bounds:
    machine.add_bound(bound.start, bound.stop)

machine.apply(emulator)


def translate_global_addr(addr):
    if addr >= 0x6000 and addr < 0x6030:
        return f"msg + {hex(addr - 0x6000)}"
    elif addr >= 0x6030 and addr < 0x6230:
        return f"buf + {hex(addr - 0x6030)}"
    elif addr >= 0x6230 and addr < 0x6238:
        return f"off + {hex(addr - 0x6230)}"
    else:
        return "invalid"


def mem_read_hook(emu, addr, size):
    expr = emu.state.inspect.mem_read_expr
    cheat = translate_global_addr(addr)
    log.warning(f"READING {hex(addr)} - {hex(addr + size)} ({cheat})")
    log.warning(f"  {expr}")
    if expr.op != "BVS" and expr.op != "BVV":
        log.error("Read from unknown global field")
        raise smallworld.emulators.angr.exceptions.PathTerminationSignal()


emulator.hook_memory_read(0x6000, 0x7000, mem_read_hook)


def mem_write_hook(emu, addr, size, data):
    expr = emu.state.inspect.mem_write_expr
    cheat = translate_global_addr(addr)
    log.warning(f"WRITING {hex(addr)} - {hex(addr + size)} ({cheat})")
    log.warning(f"  {expr}")


emulator.hook_memory_write(0x6000, 0x7000, mem_write_hook)

try:
    while True:
        emulator.step()
except smallworld.exceptions.EmulationStop:
    pass
except Exception:
    log.exception("Got exception")

print(emulator.mgr)
print(emulator.mgr.errored)
for state in emulator.mgr.deadended:
    print(state)
    state.registers.pp(log.info)
    state.memory.pp(log.info)
