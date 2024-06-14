import logging

import smallworld

smallworld.setup_logging(level=logging.INFO)
smallworld.setup_hinting(verbose=True, stream=True)

state = smallworld.cpus.AMD64CPUState()

code = smallworld.state.Code.from_filepath("hooking.bin", base=0x1000, entry=0x1000)
state.map(code)
state.rip.value = 0x1000

stack = smallworld.state.Memory(address=0xFFFF0000, size=0x1000)
stack.value = b"\x00" * 0x1000
state.map(stack)
state.rsp.value = stack.address

gets = smallworld.state.models.AMD64SystemVGetsModel(0x3800)
state.map(gets)


def puts_model(emulator):
    s = emulator.read_register("rdi")
    read = emulator.read_memory(s, 0x100)
    read = read[: read.index(b"\x00")].decode("utf-8")

    print(read)


puts = smallworld.state.models.Model(0x3808, puts_model)
state.map(puts)

emulator = smallworld.emulators.UnicornEmulator(arch=state.arch, mode=state.mode)
emulator.emulate(state)
