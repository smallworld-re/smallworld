#!/usr/bin/env python3
import logging

import smallworld

smallworld.setup_logging(level=logging.INFO)
smallworld.setup_hinting(verbose=True, stream=True, file=None)

# create a state object
cpu = smallworld.cpus.AMD64CPUState()

# load and map code into the state and set ip
code = smallworld.state.Code.from_filepath("fuzz.bin", base=0x1000, entry=0x1000)
cpu.map(code)
cpu.rip.value = 0x1000

alloc = smallworld.state.BumpAllocator(address=0x2000, size=0x1000)
user_input = None
user_input = str.encode("goodgoodgood", "utf-8")

size_addr = alloc.malloc(len(user_input), size=4)
input_addr = alloc.malloc(user_input)

cpu.map(alloc)
cpu.rdi.value = size_addr


def input_callback(uc, input, persistent_round, data):
    if len(input) > 0x1000:
        return False
    uc.mem_write(size_addr, input)


smallworld.fuzz(cpu, input_callback=input_callback)
