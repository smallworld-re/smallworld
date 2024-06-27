import logging

import smallworld

smallworld.setup_logging(level=logging.INFO)
smallworld.setup_hinting(verbose=True, stream=True, file=None)

# create a state object
state = smallworld.state.CPU.for_arch("mips", "mips64", "little")

# load and map code into the state and set ip
code = smallworld.state.Code.from_filepath(
    "stack.mips64el.bin",
    arch="mips",
    mode="mips64",
    format="blob",
    base=0x1000,
    entry=0x1000,
)
state.map(code)
state.pc.value = code.entry

# initialize some values
state.a0.value = 0x11111111
state.a1.value = 0x01010101
state.a2.value = 0x22222222
state.a3.value = 0x01010101
state.a4.value = 0x33333333
state.a5.value = 0x01010101
state.a6.value = 0x44444444
state.a7.value = 0x01010101

# create a stack and push a value
stack = smallworld.state.Stack(address=0x2000, size=0x1000, byteorder="little")
stack.push(value=0x55555555, size=4, type=int)
sp = stack.push(value=0x01010101, size=4, type=int, label="8th argument")

# map the stack into memory
state.map(stack)

# set the stack pointer
state.sp.value = sp

# emulate
emulator = smallworld.emulators.AngrEmulator(
    arch=state.arch, mode=state.mode, byteorder=state.byteorder
)
emulator.enable_linear()
final_state = emulator.emulate(state)

# read out the final state
print(final_state.v0)
