import sys

import smallworld
import logging

smallworld.logging.setup_logging(level=logging.INFO)

machine = smallworld.state.Machine()
code = smallworld.state.memory.code.Executable.from_filepath("stack.amd64.bin", address=0x1000)

platform = smallworld.platforms.Platform(
    smallworld.platforms.Architecture.X86_64, smallworld.platforms.Byteorder.LITTLE
)
cpu = smallworld.state.cpus.CPU.for_platform(platform)

cpu.rdi.set(0x11111111)
cpu.rdx.set(0x22222222)
cpu.r8.set(0x33333333)

stack = smallworld.state.memory.stack.Stack.for_platform(platform, 0x2000, 0x4000)
stack.push_integer(0xFFFFFFFF, 8, "fake return address")
stack.push_integer(0x44444444, 8, "")

rsp = stack.get_pointer() + 8
cpu.rip.set(0x1000)
cpu.rsp.set(rsp)

machine.add(cpu)
machine.add(code)
machine.add(stack)

emulator = smallworld.emulators.UnicornEmulator(platform)
emulator.add_exit_point(cpu.rip.get() + 12)


final_machine = machine.emulate(emulator)
cpu = final_machine.get_cpu()
print(hex(cpu.eax.get()))
