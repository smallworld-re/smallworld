"""Lifting BE8 ARM code with VEX.

Big-endian ARMv6 and later are BE8: data is big-endian, but instructions
are little-endian. VEX's ARM guest has one byte order for both, and a
big-endian guest will not decode single-precision VFP, so lift from a
little-endian guest and then make every load and store big-endian.
"""

import angr
import archinfo
import claripy
import pyvex
from angr.engines import UberEngine


def be8_arch() -> archinfo.Arch:
    """archinfo's ARM with big-endian data and little-endian instructions"""
    arch = archinfo.ArchARMEL(archinfo.Endness.BE)
    arch.instruction_endness = archinfo.Endness.LE
    # VEX lays out its guest state little-endian whatever the guest, with s0
    # in the low half of d0, so the register file must be little-endian.
    arch.register_endness = archinfo.Endness.LE
    # Capstone sees the instructions as they are, little-endian.
    arch.cs_mode = arch.cs_mode - archinfo.arch._capstone.CS_MODE_BIG_ENDIAN
    return arch


_LIFT_ARCH = archinfo.ArchARMEL()

_MEMORY_STMTS = (
    pyvex.stmt.Store,
    pyvex.stmt.StoreG,
    pyvex.stmt.LoadG,
    pyvex.stmt.CAS,
    pyvex.stmt.LLSC,
)


def make_big_endian(irsb: pyvex.IRSB) -> None:
    """Make every memory access in `irsb` big-endian

    This sets rather than flips, so it is safe on a cached block.
    """
    for stmt in irsb.statements:
        if isinstance(stmt, _MEMORY_STMTS):
            stmt.end = archinfo.Endness.BE
        for expr in stmt.expressions:
            if isinstance(expr, pyvex.expr.Load):
                expr.end = archinfo.Endness.BE


class BE8Engine(UberEngine):
    """angr's VEX engine, lifting BE8 code"""

    def lift_vex(self, *args, **kwargs):
        kwargs["arch"] = _LIFT_ARCH
        irsb = super().lift_vex(*args, **kwargs)
        make_big_endian(irsb)
        return irsb


class SimCCARMLinuxSyscall(angr.calling_conventions.SimCCARMLinuxSyscall):
    """angr's ARM syscall convention, reading the svc as an instruction

    angr's reads it with the data byte order, which BE8 does not share.
    """

    @staticmethod
    def syscall_num(state):
        endness = state.arch.instruction_endness
        if ((state.regs.ip_at_syscall & 1) == 1).is_true():
            insn = state.memory.load(state.regs.ip_at_syscall - 3, 2, endness=endness)
            is_svc = ((insn & 0xFF00) == 0xDF00).is_true()
            svc_num = insn & 0xFF
        else:
            insn = state.memory.load(state.regs.ip_at_syscall - 4, 4, endness=endness)
            is_svc = ((insn & 0x0F000000) == 0x0F000000).is_true()
            svc_num = insn & 0xFFFFFF
        if not is_svc:
            return claripy.BVV(0, 32)
        if (
            len(svc_num) == 32
            and (svc_num > 0x900000).is_true()
            and (svc_num < 0x90FFFF).is_true()
        ):
            return svc_num - 0x900000
        return state.regs.r7


# BE8's archinfo is ARMEL, as little-endian ARM's is.
for _os in ("default", "Linux"):
    angr.calling_conventions.register_syscall_cc("ARMEL", _os, SimCCARMLinuxSyscall)


__all__ = ["BE8Engine", "SimCCARMLinuxSyscall", "be8_arch", "make_big_endian"]
