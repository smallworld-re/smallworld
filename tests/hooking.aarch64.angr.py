import logging

import smallworld

smallworld.setup_logging(level=logging.INFO)
smallworld.setup_hinting(verbose=True, stream=True)

state = smallworld.state.CPU.for_arch("aarch64", "v8a", "little")

code = smallworld.state.Code.from_filepath(
    "hooking.aarch64.bin", arch="aarch64", mode="v8a", base=0x1000, entry=0x1010
)
state.map(code)
state.pc.value = 0x1010

stack = smallworld.state.Memory(address=0xFFFF0000, size=0x1000)
stack.value = b"\x00" * 0x1000
state.map(stack)
state.sp.value = stack.address


def gets_model(emulator):
    s = emulator.read_register("x0")
    v = input().encode("utf-8")
    emulator.write_memory(s, v)


gets = smallworld.state.models.Model(0x1004, gets_model)
state.map(gets)


def puts_model(emulator):
    s = emulator.read_register("x0")
    read = emulator.read_memory(s, 0x100)
    read = read[: read.index(b"\x00")].decode("utf-8")

    print(read)


puts = smallworld.state.models.Model(0x1008, puts_model)
state.map(puts)

emulator = smallworld.emulators.UnicornEmulator(
    arch=state.arch, mode=state.mode, byteorder=state.byteorder
)
emulator.emulate(state)
