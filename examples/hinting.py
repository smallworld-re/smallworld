from smallworld import hinting, utils
import base64

from capstone import *

hinter = hinting.getHinter(__name__)

utils.setup_hinting(verbose=True, stream=True, file="hints.jsonl")

try:
    hinter.warning("test")
except:
    pass
else:
    assert False

info_hint = hinting.UnderSpecifiedRegisterHint(
    message="This is a info hint", register="rdi"
)


hinter.info(info_hint)


CODE = b"\x55\x48\x8b\x05\xb8\x13\x00\x00"

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True


instr = None
for i in md.disasm(CODE, 0x1000):
    instr = i

print(f"instr is {instr.size} bytes: [{instr}]")

input_hint = hinting.InputUseHint(
    message="Register used in instruction has same value as Input register", 
    input_register = "rdi",
#    instruction = instr,
    instruction = base64.b64encode(instr.bytes).decode(),
    pc = 0x1000,
    use_register = "rax")


#import pdb
#pdb.set_trace()
hinter.info(input_hint)
