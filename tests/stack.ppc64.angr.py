import logging

import smallworld

smallworld.setup_logging(level=logging.INFO)
smallworld.setup_hinting(verbose=True, stream=True, file=None)

# create a state object
state = smallworld.state.CPU.for_arch("powerpc", "ppc64", "big")

# load and map code into the state and set ip
code = smallworld.state.Code.from_filepath(
    "stack.ppc64.bin",
    arch="powerpc",
    mode="ppc64",
    format="blob",
    base=0x1000,
    entry=0x1000,
)
state.map(code)
state.pc.value = code.entry

# initialize some values
state.r3.value = 0x1111
state.r4.value = 0x01010101
state.r5.value = 0x2222
state.r6.value = 0x01010101
state.r7.value = 0x3333
state.r8.value = 0x01010101
state.r9.value = 0x4444
state.r10.value = 0x01010101

# create a stack and push a value
stack = smallworld.state.Stack(address=0x2000, size=0x1000, byteorder="big")
# rsp points to the next free stack slot
stack.push(value=0x5555, size=8, type=int)
sp = stack.push(value=0x01010101, size=116, type=int, label="Unknown")

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
print(final_state.r10)
print(final_state.r3)
