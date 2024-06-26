import logging

import smallworld

smallworld.setup_logging(level=logging.INFO)
smallworld.setup_hinting(verbose=True, stream=True, file=None)

# create a state object
state = smallworld.state.CPU.for_arch("x86", "64", "little")

# load and map code into the state and set ip
code = smallworld.state.Code.from_filepath(
    "syscall.bin", arch="x86", mode="64", base=0x1000, entry=0x1000
)
state.map(code)
state.rip.value = code.entry

# create a stack and push a value
data = b"Hello, world!\n\0"
stack = smallworld.state.Stack(address=0x2000, size=0x1000)
arg1 = stack.push(value=data, size=len(data))
sp = stack.push(value=0xFFFF0000, size=8)

# map the stack into memory
state.map(stack)

# set the stack pointer
state.rsp.value = sp

# Initialize call to write():
# - edi: File descriptor 1 (stdout)
# - rsi: Buffer containing output
# - rdx: Size of output buffer
state.edi.value = 0x1
state.rsi.value = arg1
state.rdx.value = len(data) - 1

# emulate
emulator = smallworld.emulators.UnicornEmulator(
    arch=state.arch, mode=state.mode, byteorder=state.byteorder
)
final_state = emulator.emulate(state, single_step=True)

# read out the final state
print(final_state.rax)
