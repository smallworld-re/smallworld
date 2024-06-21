import logging

import smallworld

smallworld.setup_logging(level=logging.INFO)
smallworld.setup_hinting(verbose=True, stream=True, file=None)

# create a state object
state = smallworld.state.CPU.for_arch("arm", "v5t", "little")

# load and map code into the state and set ip
code = smallworld.state.Code.from_filepath("stack.armel.bin", base=0x1000, entry=0x1000)
state.map(code)
state.pc.value = code.entry

# initialize some values
state.r0.value = 0x11111111
state.r1.value = 0x01010101
state.r2.value = 0x22222222
state.r3.value = 0x01010101

# create a stack and push a value
stack = smallworld.state.Stack(address=0x2000, size=0x1000)
# rsp points to the next free stack slot
stack.push(value=0x44444444, size=4, type=int, label="5th argument")
stack.push(value=0x01010101, size=4, type=int, label="6th argument")
sp = stack.push(value=0x33333333, size=4, type=int, label="7th argument")

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
print(final_state.r0)
