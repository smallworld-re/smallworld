import logging

import smallworld

smallworld.setup_logging(level=logging.INFO)
smallworld.setup_hinting(verbose=True, stream=True)

state = smallworld.state.CPU.for_arch("mips", "mips64", "big")

code = smallworld.state.Code.from_filepath(
    "hooking.mips64.bin",
    arch="mips",
    mode="mips64",
    format="blob",
    base=0x1000,
    entry=0x1008,
)
state.map(code)
state.pc.value = 0x1008

# NOTE: Can't use the normal 0xffff0000
# That's apparently in reserved MMIO memory on MIPS.
stack = smallworld.state.Stack(address=0x7FFF0000, size=0x1000, byteorder="big")
sp = stack.push(value=0xFFFFFFFF, size=4, type=int, label="fake return address")
state.map(stack)
state.sp.value = sp


def gets_model(emulator):
    s = emulator.read_register("a0")
    v = input().encode("utf-8") + b"\x00"
    emulator.write_memory(s, v)


gets = smallworld.state.models.Model(0x1000, gets_model)
state.map(gets)


def puts_model(emulator):
    s = emulator.read_register("a0")
    v = b""
    # Reading a block of memory from angr will fail,
    # since values beyond the string buffer's bounds
    # are guaranteed to be symbolic.
    #
    # Thus, we must step one byte at a time.
    b = emulator.read_memory(s, 1)
    while b is not None and b != b"\x00":
        v = v + b
        s += 1
        b = emulator.read_memory(s, 0x1)
    if b is None:
        raise smallworld.exceptions.AnalysisError(f"Symbolic byte at 0x{s:x}")
    v = v.decode("utf-8")
    print(v)


puts = smallworld.state.models.Model(0x1004, puts_model)
state.map(puts)

emulator = smallworld.emulators.AngrEmulator(
    arch=state.arch, mode=state.mode, byteorder=state.byteorder
)
emulator.enable_linear()
final_state = emulator.emulate(state)
