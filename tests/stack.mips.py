import logging

import smallworld

smallworld.setup_logging(level=logging.INFO)
smallworld.setup_hinting(verbose=True, stream=True, file=None)

# create a state object
state = smallworld.state.CPU.for_arch("mips", "mips32", "big")

# load and map code into the state and set ip
code = smallworld.state.Code.from_filepath(
    "stack.mips.bin",
    arch="mips",
    mode="mips32",
    format="blob",
    base=0x1000,
    entry=0x1000,
)
state.map(code)
state.pc.value = code.entry

# initialize some values
state.a0.value = 0x1111
state.a1.value = 0x01010101
state.a2.value = 0x2222
state.a3.value = 0x01010101

# create a stack and push a value
stack = smallworld.state.Stack(address=0x2000, size=0x1000, byteorder="big")
# rsp points to the next free stack slot
stack.push(value=0x4444, size=4, type=int, label="7th argument")
stack.push(value=0x01010101, size=4, type=int, label="6th argument")
stack.push(value=0x3333, size=4, type=int, label="5th argument")
stack.push(value=0x01010101, size=4, type=int, label="Unknown")
stack.push(value=0x01010101, size=4, type=int, label="Unknown")
stack.push(value=0x01010101, size=4, type=int, label="Unknown")
sp = stack.push(value=0x01010101, size=4, type=int, label="Unknown")

# map the stack into memory
state.map(stack)

# set the stack pointer
state.sp.value = sp

# emulate
emulator = smallworld.emulators.UnicornEmulator(
    arch=state.arch, mode=state.mode, byteorder=state.byteorder
)
final_state = emulator.emulate(state)

# read out the final state
print(final_state.v0)
