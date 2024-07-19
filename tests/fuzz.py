#!/usr/bin/env python3

import argparse
import logging

import smallworld

smallworld.setup_logging(level=logging.INFO)
smallworld.setup_hinting(verbose=True, stream=True, file=None)

arg_parser = argparse.ArgumentParser(description="Simple harness for fuzz.bin")
arg_parser.add_argument(
    "-c", "--crash", default=False, action="store_true", help="use crashing input"
)
args = arg_parser.parse_args()

# create a state object
cpu = smallworld.cpus.AMD64CPUState()

# load and map code into the state and set ip
code = smallworld.state.Code.from_filepath("fuzz.amd64.bin", base=0x1000, entry=0x1000)
cpu.map(code)
cpu.rip.value = 0x1000

alloc = smallworld.state.BumpAllocator(address=0x2000, size=0x1000)
user_input = None
if args.crash:
    user_input = str.encode("bad!AAAAAAAA", "utf-8")
else:
    user_input = str.encode("goodgoodgood", "utf-8")

size_addr = alloc.malloc(len(user_input), size=4)
input_addr = alloc.malloc(user_input)

cpu.map(alloc)
cpu.rdi.value = size_addr
try:
    emulator = smallworld.emulators.UnicornEmulator(
        arch=cpu.arch, mode=cpu.mode, byteorder=cpu.byteorder
    )
    final_state = emulator.emulate(cpu)
    print(final_state.eax)
except Exception as e:
    print(e)
