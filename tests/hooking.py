import logging

import smallworld

smallworld.setup_logging(level=logging.INFO)
smallworld.setup_hinting(verbose=True, stream=True)

state = smallworld.cpus.AMD64CPUState()

code = smallworld.state.Code.from_filepath("hooking.bin", base=0x1000, entry=0x1000)
state.map(code)
state.rip.set(0x1000)

stack = smallworld.state.Memory(address=0xFFFF0000, size=0x1000)
stack.set(b"\x00" * 0x1000)
state.map(stack)
state.rsp.set(stack.address)


def gets_hook(emulator):
    s = emulator.read_register("rdi")
    value = input()
    emulator.write_memory(s, value.encode("utf-8"))


gets = smallworld.state.Hook(0x3800, gets_hook)
state.map(gets)


def puts_hook(emulator):
    s = emulator.read_register("rdi")
    read = emulator.read_memory(s, 0x100)
    read = read[: read.index(b"\x00")].decode("utf-8")

    print(read)


puts = smallworld.state.Hook(0x3808, puts_hook)
state.map(puts)

smallworld.emulate(state)
