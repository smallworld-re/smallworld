"""Lifting big-endian ARM code with little-endian instructions with VEX.

Big-endian ARMv6 and later are BE8: data is big-endian, but instructions
are little-endian. Big-endian AArch64 is the same. VEX's ARM guests have one
byte order for both, and the big-endian ones will not decode single-precision
VFP (ARM) or anything at all (AArch64), so lift from a little-endian guest
and then make every load and store big-endian.
"""

import typing

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


def aarch64_be_arch() -> archinfo.Arch:
    """archinfo's AArch64 with big-endian data and little-endian instructions"""
    arch = archinfo.ArchAArch64(archinfo.Endness.BE)
    arch.instruction_endness = archinfo.Endness.LE
    # VEX lays out its guest state little-endian whatever the guest.
    arch.register_endness = archinfo.Endness.LE
    # Capstone sees the instructions as they are, little-endian.
    arch.cs_mode = arch.cs_mode - archinfo.arch._capstone.CS_MODE_BIG_ENDIAN
    return arch


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


class _LittleEndianLiftEngine(UberEngine):
    """angr's VEX engine, lifting for `lift_arch` and making memory big-endian"""

    lift_arch: archinfo.Arch

    def lift_vex(self, *args, **kwargs):
        kwargs["arch"] = self.lift_arch
        irsb = super().lift_vex(*args, **kwargs)
        make_big_endian(irsb)
        return irsb


def _swapped_words(
    irsb: pyvex.IRSB, value: pyvex.expr.IRExpr
) -> typing.Tuple[int, typing.List[pyvex.stmt.IRStmt]]:
    """A temporary holding `value`'s two words swapped, and its statements"""
    lo = irsb.tyenv.add("Ity_I32")
    hi = irsb.tyenv.add("Ity_I32")
    swapped = irsb.tyenv.add("Ity_I64")
    rd = pyvex.expr.RdTmp.get_instance
    return swapped, [
        pyvex.stmt.WrTmp(lo, pyvex.expr.Unop("Iop_64to32", [value])),
        pyvex.stmt.WrTmp(hi, pyvex.expr.Unop("Iop_64HIto32", [value])),
        pyvex.stmt.WrTmp(swapped, pyvex.expr.Binop("Iop_32HLto64", [rd(lo), rd(hi)])),
    ]


def swap_exclusive_doublewords(irsb: pyvex.IRSB) -> pyvex.IRSB:
    """Put ldrexd's and strexd's first register at the lower address

    VEX lifts them as one 64-bit linked access whose low half is the first
    register, which is the word at the lower address only when data is
    little-endian. Returns a changed copy, or `irsb` if there is nothing to do.
    """

    def doubleword(stmt: pyvex.stmt.IRStmt) -> typing.Optional[pyvex.stmt.LLSC]:
        if not isinstance(stmt, pyvex.stmt.LLSC):
            return None
        if stmt.storedata is None:
            size = irsb.tyenv.lookup(stmt.result)
        else:
            size = stmt.storedata.result_type(irsb.tyenv)
        return stmt if size == "Ity_I64" else None

    if not any(doubleword(stmt) for stmt in irsb.statements):
        return irsb
    # angr caches the lifted block, so leave its copy alone.
    irsb = irsb.copy()
    statements: typing.List[pyvex.stmt.IRStmt] = []
    for stmt in irsb.statements:
        llsc = doubleword(stmt)
        if llsc is None:
            statements.append(stmt)
        elif llsc.storedata is None:
            loaded = irsb.tyenv.add("Ity_I64")
            swapped, swap = _swapped_words(irsb, pyvex.expr.RdTmp.get_instance(loaded))
            result = llsc.result
            llsc.result = loaded
            statements.append(llsc)
            statements.extend(swap)
            statements.append(
                pyvex.stmt.WrTmp(result, pyvex.expr.RdTmp.get_instance(swapped))
            )
        else:
            swapped, swap = _swapped_words(irsb, llsc.storedata)
            statements.extend(swap)
            llsc.storedata = pyvex.expr.RdTmp.get_instance(swapped)
            statements.append(llsc)
    irsb.statements = statements
    return irsb


class BE8Engine(_LittleEndianLiftEngine):
    """angr's VEX engine, lifting BE8 code"""

    lift_arch = archinfo.ArchARMEL()

    def lift_vex(self, *args, **kwargs):
        return swap_exclusive_doublewords(super().lift_vex(*args, **kwargs))


class AArch64BEEngine(_LittleEndianLiftEngine):
    """angr's VEX engine, lifting big-endian AArch64 code"""

    lift_arch = archinfo.ArchAArch64()


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


__all__ = [
    "AArch64BEEngine",
    "BE8Engine",
    "SimCCARMLinuxSyscall",
    "aarch64_be_arch",
    "be8_arch",
    "make_big_endian",
    "swap_exclusive_doublewords",
]
