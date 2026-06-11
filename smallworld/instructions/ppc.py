import capstone
import typing

from smallworld import platforms

from .bsid import BSIDMemoryReferenceOperand
from .instructions import Operand, Instruction, MemoryReferenceOperand, RegisterOperand

from .instr_use_def import analyze_bytes

class PPC32Instruction(Instruction):
    angr_arch = "PPC"
    cs_arch = capstone.CS_ARCH_PPC
    cs_mode = capstone.CS_MODE_32 | capstone.CS_MODE_BIG_ENDIAN
    ghidra_string = "PowerPC:BE:32:default"
    platform = platforms.Platform(
        platforms.Architecture.POWERPC32, platforms.Byteorder.BIG
    )

    def _memory_reference(self, operand) -> MemoryReferenceOperand:
        return BSIDMemoryReferenceOperand(
            segment=None,
            base=self._instruction.reg_name(operand.value.mem.base),
            offset=operand.value.mem.disp,
            size=4,
        )
    
    @property
    def reads(self) -> typing.Set[Operand]:
        """Registers and memory references read by this instruction.

        This is a list of string register names and dictionary memory reference
        specifications (i.e., in the form `base + scale * index + offset`).
        """
        r = analyze_bytes(self.instruction, self.ghidra_string, self.address)
        uses = []
        for u in r[0]['use']:
            if type(u) is RegisterOperand:
                if u.name is "LR":
                    uses.append(RegisterOperand("lr"))
                elif "save" in u.name or "xer" in u.name:
                    continue
                else:
                    uses.append(u)
            elif isinstance(u, MemoryReferenceOperand):
                uses.append(u)
        return uses
    

    @property
    def writes(self) -> typing.Set[Operand]:
        """Registers and memory references written by this instruction.

        Same format as `reads`.
        """
        r = analyze_bytes(self.instruction, self.ghidra_string, self.address)
        defs = []
        for d in r[0]['def']:
            if type(d) is RegisterOperand:
                if d.name == "LR":
                    defs.append(RegisterOperand("lr"))
                elif "save" in d.name or "xer" in d.name:
                    continue
                else:
                    defs.append(d)
            elif isinstance(d, MemoryReferenceOperand):
                defs.append(d)
            elif isinstance(d, tuple) and isinstance(d[0], BSIDMemoryReferenceOperand):
                defs.append(d)
            else:
                breakpoint()
                print(f"d={d} type(d)={type(d)}??")
                assert(1==0)

        return defs
    

