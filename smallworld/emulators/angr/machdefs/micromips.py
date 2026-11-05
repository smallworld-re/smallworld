import typing

import angr

from ....platforms import Architecture, Byteorder
from .machdef import GhidraMachineDef
from .mips import MIPSMachineDef
from .superh import pcode_arch


def _pin_micromips(arch) -> None:
    """Make angr's p-code lifter for ``arch`` decode microMIPS.

    The sleigh language holds both encodings and picks one with the ISA_MODE
    context bit, which defaults to standard MIPS32. angr exposes no way to set
    a context bit, so this sets the default on the lifter angr caches for the
    language. angr keys that cache by language, and only these platforms use
    the microMIPS languages, so the setting reaches nothing else. It is also
    what Block.disassembly() decodes with.
    """
    lifter = angr.engines.pcode.lifter.PcodeLifter.get_lifter(arch)
    lifter.context.setVariableDefault("ISA_MODE", 1)


class MicroMIPSReturnAddress(angr.calling_conventions.SimRegArg):
    """The return address in ra, without its ISA bit.

    A microMIPS call sets the low bit of ra to say the caller is microMIPS
    code. angr returns from a hooked function by jumping to this value, and
    an odd address would be lifted from the wrong byte.
    """

    def get_value(self, state, **kwargs):
        return super().get_value(state, **kwargs) & ~1


def _o32_cc(language: str) -> typing.Type[angr.calling_conventions.SimCC]:
    """The o32 calling convention, for one microMIPS language."""

    class SimCCMicroMIPS(angr.calling_conventions.SimCC):
        ARG_REGS = ["a0", "a1", "a2", "a3"]
        FP_ARG_REGS: typing.List[str] = []
        STACKARG_SP_BUFF = 16
        RETURN_VAL = angr.calling_conventions.SimRegArg("v0", 4)
        OVERFLOW_RETURN_VAL = angr.calling_conventions.SimRegArg("v1", 4)
        RETURN_ADDR = MicroMIPSReturnAddress("ra", 4)
        ARCH = pcode_arch(language)  # type: ignore

    return SimCCMicroMIPS


for _language in ("MIPS:BE:32:micro", "MIPS:LE:32:micro"):
    angr.calling_conventions.register_default_cc(_language, _o32_cc(_language))


# MERGE NOTE: two unmerged branches replace GhidraMachineDef's default
# angr_engine: feature/angr-pcode-float with FloatPcodeEngine (floating-point
# p-code) and feature/superh-sh1-sh2 with PcodeEngine (the partial-register
# fix). Base this class on whichever engine is the default once they merge,
# rather than on UberEnginePcode, or microMIPS loses those fixes.
class MicroMIPSEnginePcode(angr.engines.UberEnginePcode):
    """angr's p-code engine, lifting every block as microMIPS.

    This pins the encoding rather than tracking it: the ISAModeSwitch register
    that sleigh writes on a jump is ignored, so a jalx or jr into standard
    MIPS32 code still decodes as microMIPS.
    """

    def __init__(self, project, *args, **kwargs):
        super().__init__(project, *args, **kwargs)
        _pin_micromips(project.arch)

    def lift_pcode(self, *args, **kwargs):
        _pin_micromips(self.project.arch)
        return super().lift_pcode(*args, **kwargs)


class MicroMIPSMachineDef(GhidraMachineDef):
    arch = Architecture.MIPS32_MICROMIPS

    angr_engine = MicroMIPSEnginePcode

    def __init__(self):
        super().__init__()
        # The register names match angr's VEX MIPS32 machine, except that
        # sleigh calls the frame pointer s8 and the first accumulator's halves
        # hi and lo. Sleigh's FPU registers are 4 bytes, where the platform's
        # are 8, so they are left unsupported.
        self._registers = dict(MIPSMachineDef._registers)
        self._registers.update(
            {
                "fp": "s8",
                "30": "s8",
                "hi0": "hi",
                "lo0": "lo",
            }
        )
        self._registers.update({f"f{i}": None for i in range(32)})
        # The engine decodes only microMIPS, so there is no ISA mode to model.
        self._registers["isa_mode"] = None


class MicroMIPSELMachineDef(MicroMIPSMachineDef):
    byteorder = Byteorder.LITTLE
    pcode_language = "MIPS:LE:32:micro"


class MicroMIPSBEMachineDef(MicroMIPSMachineDef):
    byteorder = Byteorder.BIG
    pcode_language = "MIPS:BE:32:micro"
