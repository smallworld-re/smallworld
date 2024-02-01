import capstone as cs

import smallworld

hinter = smallworld.hinting.getHinter(__name__)

smallworld.setup_hinting(verbose=True, stream=True, file="hints.jsonl")

try:
    hinter.warning("test")
except:
    pass
else:
    assert False

info_hint = smallworld.hinting.UnderSpecifiedRegisterHint(
    message="This is a info hint", register="rdi"
)


hinter.info(info_hint)


CODE = b"\x55\x48\x8b\x05\xb8\x13\x00\x00"

md = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)
md.detail = True


instr = md.disasm(CODE, 0x1000).__next__()

print(f"instr is {instr.size} bytes: [{instr}]")

input_hint = smallworld.hinting.InputUseHint(
    message="Register used in instruction has same value as Input register",
    input_register="rdi",
    micro_exec_num=42,
    capstone_instruction=instr,
    pc=0x1000,
    use_register="rax",
    instruction_num=10,
)


hinter.info(input_hint)
