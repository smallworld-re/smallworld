#!/usr/bin/env python3
# import unicornafl
import logging
import pathlib

import smallworld

smallworld.logging.setup_logging(level=logging.INFO)


machine = smallworld.state.Machine()
platform = smallworld.platforms.Platform(
    smallworld.platforms.Architecture.X86_64, smallworld.platforms.Byteorder.LITTLE
)
cpu = smallworld.state.cpus.CPU.for_platform(platform)
code = smallworld.state.memory.code.Executable.from_filepath(
    (pathlib.Path(__file__).parent / "fuzz.amd64.bin").as_posix(), address=0x1000
)
heap = smallworld.state.memory.heap.BumpAllocator(0x2000, 0x4000)

user_input = str.encode("goodgoodgood", "utf-8")

size_addr = heap.allocate_integer(len(user_input), 4, "user input size")
input_addr = heap.allocate_bytes(user_input, "user input")

cpu.rip.set_content(0x1000)
cpu.rdi.set_content(size_addr)

machine.add(heap)
machine.add(cpu)
machine.add(code)


def input_callback(uc, input, persistent_round, data):
    if len(input) > 0x1000:
        return False
    uc.mem_write(size_addr, input)


emulator = smallworld.emulators.UnicornEmulator(platform)
machine.add_exit_point(cpu.rip.get() + 55)

machine.fuzz(emulator, input_callback)
