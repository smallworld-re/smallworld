import logging

import smallworld

smallworld.setup_logging(level=logging.INFO)
smallworld.setup_hinting(verbose=True, stream=True)

state = smallworld.state.CPU.for_arch("x86", "64", "little")
log = logging.getLogger("hook")

code = smallworld.state.Code.from_filepath(
    "hooking.bin",
    type="blob",
    arch="x86",
    mode="64",
    byteorder="little",
    base=0x1000,
    entry=0x1000,
)
state.map(code)
state.rip.value = 0x1000

stack = smallworld.state.Memory(address=0xFFFF0000, size=0x1000)
stack.value = b"\x00" * 0x1000
state.map(stack)
state.rsp.value = stack.address

gets = smallworld.state.models.AMD64SystemVGetsModel(0x3800)
state.map(gets)


def puts_model(emulator):
    log.info("puts")
    s = emulator.read_register("rdi")
    read = emulator.read_memory(s, 0x100)
    read = read[: read.index(b"\x00")].decode("utf-8")

    log.info(read)


puts = smallworld.state.models.Model(0x3808, puts_model)
state.map(puts)

emu = smallworld.emulators.AngrEmulator()
state.apply(emu)

if emu.mgr is not None and len(emu.mgr.active) > 1:
    print(emu.mgr.active[0].ip)
else:
    print("NO ACTIVE")
while emu.step():
    if emu.mgr is not None and len(emu.mgr.active) > 1:
        print(emu.mgr.active[0].ip)
    else:
        print("NO ACTIVE")
