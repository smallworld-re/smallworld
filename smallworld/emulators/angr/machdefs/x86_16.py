import typing

import angr
import archinfo
import claripy

from .... import exceptions
from ....platforms import Architecture, Byteorder
from ....platforms.defs import X86RealMode
from .machdef import GhidraMachineDef, PcodeEngine

X86_16_PCODE_LANGUAGE = "x86:LE:16:Real Mode"


class X86RealModeEnginePcode(PcodeEngine):
    """SmallWorld's p-code engine, plus sleigh's `segment`, `LOCK` and `UNLOCK`
    user ops.

    Real-mode sleigh computes every memory address with `segment(seg, off)`,
    which the x86 processor spec defines as ``(zext(seg) << 4) + zext(off)``.
    It brackets `lock`-prefixed instructions, and `xchg` with memory, in
    `LOCK()` and `UNLOCK()`, which do nothing in a single-threaded emulator.
    angr's engine rejects every user op, so these are evaluated here.
    """

    def _execute_callother(self) -> None:
        op = self._current_op
        assert op is not None
        name = op.inputs[0].getUserDefinedOpName()
        if name in ("LOCK", "UNLOCK"):
            return
        if name != "segment":
            super()._execute_callother()
            return
        assert op.output is not None
        bits = op.output.size * 8
        base = self._get_value(op.inputs[1])
        offset = self._get_value(op.inputs[2])
        result = (base.zero_extend(bits - base.size()) << 4) + offset.zero_extend(
            bits - offset.size()
        )
        self._set_value(op.output, typing.cast(claripy.ast.BV, result))


class ArchPcodeX86RealMode(archinfo.ArchPcode):
    """archinfo's view of real-mode sleigh, with 32-bit addresses.

    ArchPcode takes its width from the language's size, 16 here, but sleigh
    computes linear addresses, and every address it hands angr, in 4 bytes.
    """

    def __init__(self):
        super().__init__(X86_16_PCODE_LANGUAGE)
        self.bits = 32


class X86RealModeMachineDef(GhidraMachineDef):
    """angr machine definition for 16-bit x86 in real mode, using Ghidra's
    p-code.

    Sleigh keeps the linear pc in EIP, and infers the code segment from it,
    so code must run from a segment that starts on a 64 KiB boundary, and
    `successors()` refuses any other. See the Ghidra machine definition.
    """

    arch = Architecture.X86_16
    byteorder = Byteorder.LITTLE
    pcode_language = X86_16_PCODE_LANGUAGE

    angr_engine = X86RealModeEnginePcode

    def __init__(self):
        self._angr_arch = ArchPcodeX86RealMode()

    def successors(self, state: angr.SimState, **kwargs) -> typing.Any:
        # Sleigh infers cs from the linear pc, which only works for a cs on a
        # 64 KiB boundary; code in any other segment would run on silently
        # wrong, so refuse it instead.
        cs = typing.cast(claripy.ast.BV, state.regs.cs)
        if cs.concrete and cs.concrete_value & 0xFFF:
            raise exceptions.ConfigurationError(
                f"code segment {cs.concrete_value:#06x} does not start on a "
                "64 KiB boundary (cs must be a multiple of 0x1000), which angr's "
                "real-mode p-code requires"
            )
        return super().successors(state, **kwargs)

    def angr_reg(self, name: str) -> typing.Tuple[int, int]:
        if name == "ip":
            # archinfo folds ip into an alias for all of eip, the program
            # counter; sleigh's IP is its low half.
            offset, _ = super().angr_reg("pc")
            return offset, 2
        return super().angr_reg(name)

    # Sleigh uses SmallWorld's names, apart from these.
    _registers: typing.Dict[str, typing.Optional[str]] = {  # type: ignore[assignment]
        **{name: name for name in X86RealMode.registers},
        "pc": "eip",
        # NOTE: Sleigh's EIP is the linear pc, not the offset into cs.
        "eip": None,
    }


class SimRealModeReturnAddr(angr.calling_conventions.SimStackArg):
    """The 2-byte return offset a near call leaves at ss:sp.

    angr returns from a hook to wherever this points, so it reads the offset
    through ss and returns the linear address it names in cs, where a plain
    stack argument would read the flat address sp and jump to the offset.
    """

    def __init__(self):
        super().__init__(0, 2)

    def _address(self, state, stack_base):
        if stack_base is None:
            stack_base = state.regs.sp
        return (state.regs.ss.zero_extend(16) << 4) + (
            stack_base + self.stack_offset
        ).zero_extend(16)

    def get_value(self, state, stack_base=None, **kwargs):
        ip = state.memory.load(
            self._address(state, stack_base),
            endness=state.arch.memory_endness,
            size=self.size,
        )
        return (state.regs.cs.zero_extend(16) << 4) + ip.zero_extend(16)

    def set_value(self, state, value, stack_base=None, **kwargs):
        # A linear address is stored as its offset into cs.
        if isinstance(value, int):
            value = claripy.BVV(value, 32)
        ip = value - (state.regs.cs.zero_extend(16) << 4)
        state.memory.store(
            self._address(state, stack_base),
            ip[15:0],
            endness=state.arch.memory_endness,
        )


class SimCCX86RealMode(angr.calling_conventions.SimCC):
    """16-bit near cdecl calling convention.

    Arguments are all passed on the stack, above the 2-byte return address
    a near call pushes, and integers come back in ax (or dx:ax). The return
    address is the offset at ss:sp, into cs.
    """

    ARG_REGS: typing.List[str] = []
    FP_ARG_REGS: typing.List[str] = []
    STACKARG_SP_DIFF = 2
    RETURN_VAL = angr.calling_conventions.SimRegArg("ax", 2)
    OVERFLOW_RETURN_VAL = angr.calling_conventions.SimRegArg("dx", 2)
    RETURN_ADDR = SimRealModeReturnAddr()
    ARCH = ArchPcodeX86RealMode()  # type: ignore


angr.calling_conventions.register_default_cc(X86_16_PCODE_LANGUAGE, SimCCX86RealMode)
