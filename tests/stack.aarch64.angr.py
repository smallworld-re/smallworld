import logging

import smallworld

smallworld.setup_logging(level=logging.INFO)
smallworld.setup_hinting(verbose=True, stream=True, file=None)

# create a state object
state = smallworld.state.CPU.for_arch("aarch64", "v8a", "little")

# load and map code into the state and set ip
code = smallworld.state.Code.from_filepath(
    "stack.aarch64.bin",
    arch="aarch64",
    mode="v8a",
    format="blob",
    base=0x1000,
    entry=0x1000,
)
state.map(code)
state.pc.value = code.entry

# initialize some values
state.w0.value = 0x11111111
state.w1.value = 0x01010101
state.w2.value = 0x22222222
state.w3.value = 0x01010101
state.w4.value = 0x33333333
state.w5.value = 0x01010101
state.w6.value = 0x44444444
state.w7.value = 0x01010101

# create a stack and push a value
stack = smallworld.state.Stack(address=0x2000, size=0x1000)
# sp points to the next free stack slot
sp = stack.push(value=0x55555555, size=8, type=int, label="7th argument")

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
print(final_state.x0)
