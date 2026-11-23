"""Lifting ARMv8's ties-away rounding and maxNum/minNum with VEX.

VEX lifts the instructions that round to nearest with ties away from zero
(A32/T32 vrinta and vcvta, AArch64 frinta, fcvtas and fcvtau) with rounding
mode 0, which is ties to even, and angr can't run VEX's ties-away mode (4).
It also lifts A32/T32 vmaxnm and vminnm to Iop_MaxNum and Iop_MinNum, which
angr doesn't implement. Rewrite both after lifting, with operations angr
runs.

The mode-0 operations are the same as those of the instructions that do
round ties to even (vrintn, frintn, ...), so the rewrite finds the ties-away
ones by decoding the instruction each belongs to.
"""

import typing

import pyvex
from angr.engines import UberEngine

from .be8 import AArch64BEEngine, BE8Engine
from .v8m import instruction_bytes, lift_source

# (mask, value) of the ties-away instructions, as 32-bit words: A32 and
# AArch64 words are little-endian, and a T32 word is its first halfword
# then its second.
_A32_TIES_AWAY = (
    # vrinta (floating point): 1111 1110 1D11 10 RM=00 Vd 10 size 01 M 0 Vm
    (0xFFBF0CD0, 0xFEB80840),
    # vcvta (floating point): 1111 1110 1D11 11 RM=00 Vd 10 size op 1 M 0 Vm
    (0xFFBF0C50, 0xFEBC0840),
    # vrinta (Advanced SIMD): 1111 0011 1D11 size 10 Vd 01 op=010 Q M 0 Vm
    (0xFFB30F90, 0xF3B20500),
    # vcvta (Advanced SIMD): 1111 0011 1D11 size 11 Vd 00 RM=00 op Q M 0 Vm
    (0xFFB30F10, 0xF3B30000),
)
_T32_TIES_AWAY = (
    _A32_TIES_AWAY[0],
    _A32_TIES_AWAY[1],
    # Advanced SIMD is 1111 1111 in T32 where A32 has 1111 0011.
    (0xFFB30F90, 0xFFB20500),
    (0xFFB30F10, 0xFFB30000),
)
_A64_TIES_AWAY = (
    # frinta (scalar): 0001 1110 ftype 1 001 100 10000 Rn Rd
    (0xFF3FFC00, 0x1E264000),
    # fcvtas, fcvtau (scalar, to a general register):
    # sf 001 1110 ftype 1 00 10U 000000 Rn Rd
    (0x7F3EFC00, 0x1E240000),
    # fcvtas, fcvtau (vector): 0 Q U 01110 0 sz 10000 11100 10 Rn Rd
    (0x9FBFFC00, 0x0E21C800),
    # fcvtas, fcvtau (scalar SIMD): 01 U 11110 0 sz 10000 11100 10 Rn Rd
    (0xDFBFFC00, 0x5E21C800),
    # frinta (vector): 0 Q 1 01110 0 sz 10000 11000 10 Rn Rd
    (0xBFBFFC00, 0x2E218800),
)

# Floating-point (not Advanced SIMD) vmaxnm and vminnm: bits 27:23 = 11101
_A32_FP_MASK, _A32_FP_VALUE = 0x0F800000, 0x0E800000

# Operations that take a rounding mode and round a float to an integer
_ROUNDING_OPS = {
    "Iop_RoundF32toInt": "F32",
    "Iop_RoundF64toInt": "F64",
    "Iop_F32toI32S": "F32",
    "Iop_F32toI32U": "F32",
    "Iop_F32toI64S": "F32",
    "Iop_F32toI64U": "F32",
    "Iop_F64toI32S": "F64",
    "Iop_F64toI32U": "F64",
    "Iop_F64toI64S": "F64",
    "Iop_F64toI64U": "F64",
}

_MIN_MAX_OPS = {
    "Iop_MaxNumF32": ("F32", True),
    "Iop_MaxNumF64": ("F64", True),
    "Iop_MinNumF32": ("F32", False),
    "Iop_MinNumF64": ("F64", False),
}

# VEX's rounding mode towards zero
_ROUND_TOWARDS_ZERO = 3

# Iop_CmpF results
_CMP_GT, _CMP_LT, _CMP_EQ, _CMP_UNORDERED = 0x00, 0x01, 0x40, 0x45

# FPSCR.DN: NaN results are the default NaN.
_FPSCR_DN = 1 << 25


class _Format(typing.NamedTuple):
    bits: int
    quiet: int
    default_nan: int


_FORMATS = {
    "F32": _Format(32, 0x00400000, 0x7FC00000),
    "F64": _Format(64, 0x0008000000000000, 0x7FF8000000000000),
}


def _matches(word: int, encodings) -> bool:
    return any(word & mask == value for mask, value in encodings)


def _constant(
    expr: pyvex.expr.IRExpr, constants: typing.Mapping[int, int]
) -> typing.Optional[int]:
    """expr's value, if it is a constant or a temporary holding one"""
    if isinstance(expr, pyvex.expr.Const):
        return expr.con.value
    if isinstance(expr, pyvex.expr.RdTmp):
        return constants.get(expr.tmp)
    return None


def _word(insn: bytes, thumb: bool) -> int:
    if thumb:
        return int.from_bytes(insn[0:2], "little") << 16 | int.from_bytes(
            insn[2:4], "little"
        )
    return int.from_bytes(insn, "little")


class _Builder:
    """Appends flat IR statements that compute into new temporaries"""

    def __init__(self, irsb: pyvex.IRSB):
        self.irsb = irsb
        self.stmts: typing.List[pyvex.stmt.IRStmt] = []

    def tmp(self, ty: str, expr: pyvex.expr.IRExpr) -> pyvex.expr.RdTmp:
        tmp = self.irsb.tyenv.add(ty)
        self.stmts.append(pyvex.stmt.WrTmp(tmp, expr))
        return pyvex.expr.RdTmp.get_instance(tmp)

    def op(self, name: str, ty: str, *args: pyvex.expr.IRExpr) -> pyvex.expr.RdTmp:
        kind = {1: pyvex.expr.Unop, 2: pyvex.expr.Binop, 3: pyvex.expr.Triop}
        return self.tmp(ty, kind[len(args)](name, list(args)))

    def ite(
        self,
        ty: str,
        cond: pyvex.expr.IRExpr,
        iftrue: pyvex.expr.IRExpr,
        iffalse: pyvex.expr.IRExpr,
    ) -> pyvex.expr.RdTmp:
        return self.tmp(ty, pyvex.expr.ITE(cond, iffalse, iftrue))

    @staticmethod
    def const(bits: int, value: int) -> pyvex.expr.Const:
        return pyvex.expr.Const(
            {1: pyvex.const.U1, 32: pyvex.const.U32, 64: pyvex.const.U64}[bits](value)
        )

    def float_const(self, fmt: str, bits: int) -> pyvex.expr.RdTmp:
        size = _FORMATS[fmt].bits
        return self.op(
            f"Iop_ReinterpI{size}as{fmt}", f"Ity_{fmt}", self.const(size, bits)
        )

    def compare(
        self, fmt: str, a: pyvex.expr.IRExpr, b: pyvex.expr.IRExpr, result: int
    ) -> pyvex.expr.RdTmp:
        """Whether Iop_CmpF of a and b gives `result`"""
        cmp = self.op(f"Iop_Cmp{fmt}", "Ity_I32", a, b)
        return self.op("Iop_CmpEQ32", "Ity_I1", cmp, self.const(32, result))

    def and1(self, *conds: pyvex.expr.IRExpr) -> pyvex.expr.RdTmp:
        """The conjunction of I1 conditions, through I32"""
        acc = self.op("Iop_1Uto32", "Ity_I32", conds[0])
        for cond in conds[1:]:
            acc = self.op(
                "Iop_And32", "Ity_I32", acc, self.op("Iop_1Uto32", "Ity_I32", cond)
            )
        return self.op("Iop_CmpNE32", "Ity_I1", acc, self.const(32, 0))

    def not1(self, cond: pyvex.expr.IRExpr) -> pyvex.expr.RdTmp:
        return self.op(
            "Iop_CmpEQ32",
            "Ity_I1",
            self.op("Iop_1Uto32", "Ity_I32", cond),
            self.const(32, 0),
        )


def _round_ties_away(b: _Builder, fmt: str, x: pyvex.expr.IRExpr) -> pyvex.expr.RdTmp:
    """x rounded to an integral float, ties away from zero"""
    ty = f"Ity_{fmt}"
    rz = b.const(32, _ROUND_TOWARDS_ZERO)
    truncated = b.op(f"Iop_Round{fmt}toInt", ty, rz, x)
    # x minus its truncation is exact: it is x's fraction.
    fraction = b.op(f"Iop_Sub{fmt}", ty, rz, x, truncated)
    magnitude = b.op(f"Iop_Abs{fmt}", ty, fraction)
    half = b.float_const(fmt, 0x3F000000 if fmt == "F32" else 0x3FE0000000000000)
    # At least a half: greater or equal, not less or unordered (NaN).
    at_least_half = b.op(
        "Iop_CmpEQ32",
        "Ity_I1",
        b.op(
            "Iop_And32",
            "Ity_I32",
            b.op(f"Iop_Cmp{fmt}", "Ity_I32", magnitude, half),
            b.const(32, _CMP_LT),
        ),
        b.const(32, 0),
    )
    one, minus_one = (
        (0x3F800000, 0xBF800000)
        if fmt == "F32"
        else (0x3FF0000000000000, 0xBFF0000000000000)
    )
    zero = b.float_const(fmt, 0)
    negative = b.compare(fmt, fraction, zero, _CMP_LT)
    step = b.ite(ty, negative, b.float_const(fmt, minus_one), b.float_const(fmt, one))
    stepped = b.op(f"Iop_Add{fmt}", ty, rz, truncated, step)
    rounded = b.ite(ty, at_least_half, stepped, truncated)
    # A zero result has x's sign (vrinta of -0.25 is -0), which angr's
    # rounding drops; x times zero is the zero with x's sign.
    signed_zero = b.op(f"Iop_Mul{fmt}", ty, rz, x, zero)
    return b.ite(ty, b.compare(fmt, rounded, zero, _CMP_EQ), signed_zero, rounded)


def _min_max_num(
    b: _Builder,
    fmt: str,
    maximum: bool,
    a: pyvex.expr.IRExpr,
    bb: pyvex.expr.IRExpr,
    default_nan: pyvex.expr.IRExpr,
) -> pyvex.expr.RdTmp:
    """ARM's FPMaxNum or FPMinNum of a and bb (without flushing denormals)

    See the Ghidra emulator's fp_max_num userop, which this mirrors.
    """
    form = _FORMATS[fmt]
    size = form.bits
    ity = f"Ity_I{size}"
    ai = b.op(f"Iop_Reinterp{fmt}asI{size}", ity, a)
    bi = b.op(f"Iop_Reinterp{fmt}asI{size}", ity, bb)

    def is_nan(x):
        return b.compare(fmt, x, x, _CMP_UNORDERED)

    def is_quiet(xi):
        return b.op(
            f"Iop_CmpNE{size}",
            "Ity_I1",
            b.op(f"Iop_And{size}", ity, xi, b.const(size, form.quiet)),
            b.const(size, 0),
        )

    def quieted(xi):
        return b.op(f"Iop_Or{size}", ity, xi, b.const(size, form.quiet))

    a_nan, b_nan = is_nan(a), is_nan(bb)
    a_quiet, b_quiet = is_quiet(ai), is_quiet(bi)

    # Two numbers: the larger (smaller), and of equal ones, whose bits
    # differ only for zeros of opposite sign, +0 for the maximum and -0 for
    # the minimum.
    greater = b.compare(fmt, a, bb, _CMP_GT)
    larger, smaller = b.ite(ity, greater, ai, bi), b.ite(ity, greater, bi, ai)
    equal = b.compare(fmt, a, bb, _CMP_EQ)
    equal_result = b.op(f"Iop_{'And' if maximum else 'Or'}{size}", ity, ai, bi)
    number = b.ite(ity, equal, equal_result, larger if maximum else smaller)

    # A NaN: the default NaN, or a signalling one, quieted, before a quiet
    # one, and the first before the second.
    a_signalling = b.and1(a_nan, b.not1(a_quiet))
    b_signalling = b.and1(b_nan, b.not1(b_quiet))
    propagated = b.ite(
        ity,
        a_signalling,
        quieted(ai),
        b.ite(
            ity,
            b_signalling,
            quieted(bi),
            b.ite(ity, a_nan, quieted(ai), quieted(bi)),
        ),
    )
    nan = b.ite(ity, default_nan, b.const(size, form.default_nan), propagated)

    either_nan = b.not1(b.and1(b.not1(a_nan), b.not1(b_nan)))
    result = b.ite(ity, either_nan, nan, number)
    # A quiet NaN loses to a number.
    result = b.ite(ity, b.and1(b_nan, b_quiet, b.not1(a_nan)), ai, result)
    result = b.ite(ity, b.and1(a_nan, a_quiet, b.not1(b_nan)), bi, result)
    return b.op(f"Iop_ReinterpI{size}as{fmt}", f"Ity_{fmt}", result)


def rewrite(
    irsb: pyvex.IRSB, insn_at: typing.Callable[[int], typing.Optional[bytes]]
) -> pyvex.IRSB:
    """Rewrite irsb's ties-away rounding and maxNum/minNum, if it has any.

    `insn_at` returns the 4 bytes at an address, or None.
    Returns irsb, or a rewritten copy: angr caches the lifted block.
    """
    if irsb.statements is None:
        return irsb
    aarch64 = irsb.arch.name == "AARCH64"
    found = []
    imark = None
    # Unoptimized IR (angr lifts so when it supports self-modifying code)
    # passes the rounding mode through a temporary.
    constants: typing.Dict[int, int] = {}
    for index, stmt in enumerate(irsb.statements):
        if isinstance(stmt, pyvex.stmt.IMark):
            imark = stmt
            continue
        if not isinstance(stmt, pyvex.stmt.WrTmp) or imark is None:
            continue
        data = stmt.data
        if isinstance(data, pyvex.expr.Const):
            constants[stmt.tmp] = data.con.value
        if not isinstance(data, pyvex.expr.Binop):
            continue
        if data.op in _MIN_MAX_OPS:
            found.append((index, imark))
        elif data.op in _ROUNDING_OPS and _constant(data.args[0], constants) == 0:
            found.append((index, imark))
    if not found:
        return irsb

    def word(imark: pyvex.stmt.IMark) -> typing.Optional[int]:
        insn = insn_at(imark.addr)
        if insn is None:
            return None
        return _word(insn, imark.delta == 1)

    rewrites = []
    for index, imark in found:
        data = irsb.statements[index].data
        insn = word(imark)
        if insn is None:
            continue
        if data.op in _MIN_MAX_OPS:
            rewrites.append((index, insn))
            continue
        encodings = (
            _A64_TIES_AWAY
            if aarch64
            else _T32_TIES_AWAY if imark.delta == 1 else _A32_TIES_AWAY
        )
        if _matches(insn, encodings):
            rewrites.append((index, insn))
    if not rewrites:
        return irsb

    irsb = irsb.copy()
    fpscr = None if aarch64 else irsb.arch.get_register_offset("fpscr")
    for index, insn in reversed(rewrites):
        stmt = irsb.statements[index]
        data = stmt.data
        b = _Builder(irsb)
        if data.op in _MIN_MAX_OPS:
            fmt, maximum = _MIN_MAX_OPS[data.op]
            if fpscr is not None and insn & _A32_FP_MASK == _A32_FP_VALUE:
                # Floating point: FPSCR.DN chooses the default NaN.
                default_nan = b.op(
                    "Iop_CmpNE32",
                    "Ity_I1",
                    b.op(
                        "Iop_And32",
                        "Ity_I32",
                        b.tmp("Ity_I32", pyvex.expr.Get(fpscr, "Ity_I32")),
                        b.const(32, _FPSCR_DN),
                    ),
                    b.const(32, 0),
                )
            else:
                # Advanced SIMD always uses the default NaN.
                default_nan = b.const(1, 1)
            a, bb = data.args
            value = _min_max_num(b, fmt, maximum, a, bb, default_nan)
        else:
            fmt = _ROUNDING_OPS[data.op]
            rounded = _round_ties_away(b, fmt, data.args[1])
            if data.op.startswith("Iop_Round"):
                value = rounded
            else:
                # Converting an integral value rounds nothing.
                value = b.op(
                    data.op,
                    irsb.tyenv.lookup(stmt.tmp),
                    b.const(32, _ROUND_TOWARDS_ZERO),
                    rounded,
                )
        irsb.statements[index : index + 1] = b.stmts + [
            pyvex.stmt.WrTmp(stmt.tmp, value)
        ]
    return irsb


class V8FPMixin:
    """Rewrites ARMv8's ties-away rounding and maxNum/minNum after lifting.

    Mix into angr's VEX engine, or one derived from it.
    """

    def lift_vex(self, *args, **kwargs):
        irsb = super().lift_vex(*args, **kwargs)  # type: ignore[misc]
        addr, state, clemory, insn_bytes, offset = lift_source(args, kwargs)
        block = irsb.addr if addr is None else addr
        return rewrite(
            irsb,
            lambda at: instruction_bytes(at, block, state, clemory, insn_bytes, offset),
        )


class V8FPEngine(V8FPMixin, UberEngine):
    """angr's VEX engine, with ARMv8's ties-away rounding and maxNum/minNum"""


class BE8V8FPEngine(V8FPMixin, BE8Engine):
    """BE8Engine, with ARMv8's ties-away rounding and maxNum/minNum"""


class AArch64BEV8FPEngine(V8FPMixin, AArch64BEEngine):
    """AArch64BEEngine, with ARMv8's ties-away rounding"""


__all__ = [
    "AArch64BEV8FPEngine",
    "BE8V8FPEngine",
    "V8FPEngine",
    "V8FPMixin",
    "rewrite",
]
