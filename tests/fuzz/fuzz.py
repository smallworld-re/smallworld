#!/usr/bin/env python3

import argparse
import logging

import smallworld

smallworld.logging.setup_logging(level=logging.INFO)

arg_parser = argparse.ArgumentParser(description="Simple harness for fuzz.bin")
arg_parser.add_argument(
    "-c", "--crash", default=False, action="store_true", help="use crashing input"
)
args = arg_parser.parse_args()

machine = smallworld.state.Machine()
platform = smallworld.platforms.Platform(
    smallworld.platforms.Architecture.X86_64, smallworld.platforms.Byteorder.LITTLE
)
cpu = smallworld.state.cpus.CPU.for_platform(platform)
code = smallworld.state.memory.code.Executable.from_filepath(
    __file__.replace(".py", ".bin").replace(".angr", ""), address=0x1000
)
heap = smallworld.state.memory.heap.BumpAllocator(0x2000, 0x1000)

user_input = None
if args.crash:
    user_input = str.encode("bad!AAAAAAAA", "utf-8")
else:
    user_input = str.encode("goodgoodgood", "utf-8")

size_addr = heap.allocate_integer(len(user_input), 4, "user input size")
input_addr = heap.allocate_bytes(user_input, "user input")

cpu.rip.set_content(0x1000)
cpu.rdi.set_content(size_addr)

machine.add(heap)
machine.add(cpu)
machine.add(code)
emulator = smallworld.emulators.UnicornEmulator(platform)
emulator.add_exit_point(cpu.rip.get() + 55)
final_machine = machine.emulate(emulator)
final_cpu = final_machine.get_cpu()
print(final_machine.get_cpu().eax.get())
