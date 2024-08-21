import logging

import smallworld

smallworld.setup_logging(level=logging.INFO)
smallworld.setup_hinting(verbose=True, stream=True)

state = smallworld.state.CPU.for_arch("mips", "mips32", "little")

code = smallworld.state.Code.from_filepath(
    "hooking.mipsel.bin",
    arch="mips",
    mode="mips32",
    format="blob",
    base=0x1000,
    entry=0x1008,
)
state.map(code)
state.pc.value = 0x1008

# NOTE: Can't use the normal 0xffff0000
# That's apparently in reserved MMIO memory on MIPS.
stack = smallworld.state.Stack(address=0x7FFF0000, size=0x1000, byteorder="little")
sp = stack.push(value=0xFFFFFFFF, size=4, type=int, label="fake return address")
state.map(stack)
state.sp.value = sp


def gets_model(emulator):
    s = emulator.read_register("a0")
    v = input().encode("utf-8")
    emulator.write_memory(s, v)


gets = smallworld.state.models.Model(0x1000, gets_model)
state.map(gets)


def puts_model(emulator):
    s = emulator.read_register("a0")
    read = emulator.read_memory(s, 0x100)
    read = read[: read.index(b"\x00")].decode("utf-8")

    print(read)


puts = smallworld.state.models.Model(0x1004, puts_model)
state.map(puts)

emulator = smallworld.emulators.UnicornEmulator(
    arch=state.arch, mode=state.mode, byteorder=state.byteorder
)
final_state = emulator.emulate(state)
