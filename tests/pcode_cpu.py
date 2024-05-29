from smallworld.cpus import AMD64CPUState, PcodeCPUState
from smallworld.state import Register, RegisterAlias


class PcodeAMD64CPUState(PcodeCPUState):
    arch = "x86"
    mode = "64"

    def __init__(self):
        super().__init__("x86:LE:64:default")


pcode_cpu = PcodeAMD64CPUState()
manual_cpu = AMD64CPUState

for name in dir(manual_cpu):
    m_reg = getattr(manual_cpu, name)

    if not isinstance(m_reg, Register) and not isinstance(m_reg, RegisterAlias):
        continue

    if not hasattr(pcode_cpu, name):
        print(f"{name}: Missing")
        continue

    p_reg = getattr(pcode_cpu, name)
    if not isinstance(p_reg, Register) and not isinstance(p_reg, RegisterAlias):
        print(f"{name}: Missing")
        continue

    if isinstance(m_reg, Register):
        if not isinstance(p_reg, Register):
            print(f"{name} incorrect: Expected register, got alias")
        elif m_reg.width != p_reg.width:
            print(f"{name} incorrect: Expected {m_reg.width} bytes, got {p_reg.width}")
    if isinstance(m_reg, RegisterAlias):
        if not isinstance(p_reg, RegisterAlias):
            print(f"{name} incorrect: Expected alias, got register")
        else:
            if m_reg.width != p_reg.width:
                print(
                    f"{name} incorrect: Expected size {m_reg.width} bytes, got {p_reg.width}"
                )
            if m_reg.reference.name != p_reg.reference.name:
                print(
                    f"{name} incorrect: Expected ref to {m_reg.reference}, got {p_reg.reference}"
                )
            if m_reg.offset != p_reg.offset:
                print(
                    f"{name} incorrect: Expected offset {m_reg.offset} bytes, got {p_reg.offset}"
                )
