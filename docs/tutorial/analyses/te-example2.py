

import sys

import smallworld
from smallworld.analyses.trace_execution import TraceExecution, TraceExecutionCBPoint

# configure the platform for emulation
platform = smallworld.platforms.Platform(
    smallworld.platforms.Architecture.X86_64, smallworld.platforms.Byteorder.LITTLE
)

machine = smallworld.state.Machine()

cpu = smallworld.state.cpus.CPU.for_platform(platform)

code = smallworld.state.memory.code.Executable.from_elf(
    open(f"te-example", "rb"), address=0x0
)
machine.add(code)

stack = smallworld.state.memory.stack.Stack.for_platform(platform, 0x10000, 0x4000)
machine.add(stack)
rsp = stack.get_pointer()
cpu.rsp.set(rsp)

entry_point = 0x1149
exit_point = entry_point+0xbb

cpu.rip.set(entry_point)
machine.add(cpu)
machine.add_exit_point(exit_point)

inp = int(sys.argv[1])
print(f"function input = {inp}")

cpu.rdi.set(inp)

arr = []
def before_cb(emu, pc, te):
    global arr
    if pc == 0x00001185:
        arr.append(emu.read_register("eax"))

def collect_hints(h):
    for te in h.trace:
        print(te)
            
hinter = smallworld.hinting.Hinter()
hinter.register(smallworld.hinting.TraceExecutionHint, collect_hints)
ta = TraceExecution(hinter, num_insns=10000)
ta.register_cb(TraceExecutionCBPoint.BEFORE_INSTRUCTION, before_cb)
ta.run(machine)

print(arr)


