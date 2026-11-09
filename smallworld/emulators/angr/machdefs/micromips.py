import typing

import angr
import archinfo
import pypcode

from ....platforms import Architecture, Byteorder
from .machdef import GhidraMachineDef
from .mips import MIPSMachineDef
from .superh import pcode_arch


def _micromips_context(language: str) -> pypcode.Context:
    """A sleigh context for ``language`` that decodes microMIPS everywhere.

    The language holds both encodings and picks one with the ISA_MODE context
    bit, which defaults to standard MIPS32; this makes microMIPS the default.
    """
    context = pypcode.Context(language)
    context.setVariableDefault("ISA_MODE", 1)
    return context


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

    angr exposes no way to set a context bit, so the engine gives the lifter
    angr caches for the language its own context, one that decodes microMIPS
    by default. angr shares that lifter among every project in the process,
    Block.disassembly() included.

    Pinning the default is not enough on its own. Decoding a jalx runs sleigh's
    globalset, which records in the context that everything from the jump
    target up is standard MIPS32, and that record outlives the lift: later
    blocks, and later emulators, would decode that code as MIPS32. The engine
    replaces the context whenever it may hold such a record: when the engine
    is created, after lifting a block with a jalx in it, and before lifting
    at an address that no longer decodes as microMIPS, which catches a jalx
    lifted by something other than this engine. pypcode's own Context.reset()
    would clear the record too, but it frees the translator that p-code
    lifted earlier still points into.
    """

    def __init__(self, project, *args, **kwargs):
        super().__init__(project, *args, **kwargs)
        arch = project.arch
        self._lifter = angr.engines.pcode.lifter.PcodeLifter.get_lifter(arch)
        # Two 16-bit nops: one 2-byte instruction as microMIPS, but a 4-byte
        # jal as standard MIPS32.
        nop16 = (0x0C00).to_bytes(
            2, "big" if arch.memory_endness == archinfo.Endness.BE else "little"
        )
        self._canary = nop16 * 2
        self._refresh_context()

    def _refresh_context(self) -> None:
        self._lifter.context = _micromips_context(self.project.arch.name)

    def _decodes_micromips(self, addr: int) -> bool:
        try:
            insns = self._lifter.context.disassemble(
                self._canary, addr, max_instructions=1
            ).instructions
        except (pypcode.BadDataError, pypcode.DecoderError, pypcode.LowlevelError):
            return False
        return len(insns) == 1 and insns[0].length == 2

    def lift_pcode(self, addr=None, state=None, *args, **kwargs):
        # angr's lift_vex passes everything positionally.
        where = addr
        if where is None and state is not None:
            where = state.solver.eval(state._ip)
        if where is not None and not self._decodes_micromips(where):
            self._refresh_context()

        irsb = super().lift_pcode(addr, state, *args, **kwargs)

        disassembly = getattr(irsb, "disassembly", None)
        if disassembly is not None and any(
            insn.mnemonic == "jalx" for insn in disassembly.insns
        ):
            self._refresh_context()
        return irsb


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

    def pc_value(self, pc: int) -> int:
        # An odd pc selects microMIPS, the only encoding the engine decodes,
        # so the bit says nothing; the address is the even part.
        return pc & ~1


class MicroMIPSELMachineDef(MicroMIPSMachineDef):
    byteorder = Byteorder.LITTLE
    pcode_language = "MIPS:LE:32:micro"


class MicroMIPSBEMachineDef(MicroMIPSMachineDef):
    byteorder = Byteorder.BIG
    pcode_language = "MIPS:BE:32:micro"
