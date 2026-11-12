"""Floating-point p-code operations for angr's p-code engine.

angr's p-code engine leaves every floating-point operation unimplemented:
each ``OpBehaviorFloat*`` in ``angr/engines/pcode/behavior.py`` raises
"Not implemented!". :class:`FloatPcodeEngine` runs blocks with the behaviors
here instead.

The semantics follow IEEE 754. P-code operations have no rounding mode, so
results are rounded to nearest, ties to even. Where IEEE 754 leaves a result
open, or has no matching operation:

- A NaN result is the canonical quiet NaN. ``FLOAT_NEG`` and ``FLOAT_ABS``
  change only the sign bit, of a NaN too.
- A comparison with a NaN is unordered: ``FLOAT_EQUAL``, ``FLOAT_LESS`` and
  ``FLOAT_LESSEQUAL`` are false, and ``FLOAT_NOTEQUAL`` is true. -0 equals
  +0. (The p-code reference says ``FLOAT_NOTEQUAL`` is false on a NaN; IEEE
  754 and Ghidra's emulator say true.)
- ``FLOAT_TRUNC`` truncates toward zero, and saturates to the output's
  signed range. NaN converts to 0.
- ``FLOAT_ROUND`` rounds halfway cases up, ``floor(x + 1/2)``, computed
  exactly; this is what Ghidra computes, though IEEE 754 has no such
  operation. ``FLOAT_CEIL`` and ``FLOAT_FLOOR`` keep the sign of a zero
  result.

``docs/concepts/platforms/support.rst`` lists where Ghidra's emulator departs
from IEEE 754, and so from these behaviors.

Concrete operands are computed with Python floats, so that every rounding is
correct and independent of claripy, which ignores the rounding mode when it
folds constants. Half-, single- and double-precision operations computed in
double precision and then rounded are correctly rounded, because double
carries more than twice their precision plus two bits.

Symbolic operands are computed with claripy's floating-point operations, which
Z3 solves. Claripy only has single and double precision, so a symbolic
half-precision operand is refused, except by ``FLOAT_NEG`` and ``FLOAT_ABS``,
which only change its sign bit. No floating-point format other than half,
single and double precision is supported; in particular, not the 80-bit
formats of x87 and the 68881.
"""

import fractions
import math
import struct
import typing

import angr
import claripy
from angr.engines.pcode.behavior import BehaviorFactory, OpBehavior
from pypcode import OpCode

from .... import exceptions

_FORMATS = {2: "<e", 4: "<f", 8: "<d"}
_SORTS = {4: claripy.FSORT_FLOAT, 8: claripy.FSORT_DOUBLE}
_CANONICAL_NAN = {2: 0x7E00, 4: 0x7FC00000, 8: 0x7FF8000000000000}
# Significand bits including the implicit bit. A float at least this many
# powers of two in magnitude is already an integer.
_PRECISION = {2: 11, 4: 24, 8: 53}

_RNE = claripy.fp.RM.RM_NearestTiesEven
_RTZ = claripy.fp.RM.RM_TowardsZero
_RTP = claripy.fp.RM.RM_TowardsPositiveInf
_RTN = claripy.fp.RM.RM_TowardsNegativeInf


def _int_range(size: int) -> typing.Tuple[int, int]:
    bits = size * 8
    return -(1 << (bits - 1)), (1 << (bits - 1)) - 1


def _check_format(size: int) -> None:
    if size not in _FORMATS:
        raise exceptions.EmulationError(
            f"angr has no {size * 8}-bit floating-point format"
        )


# Concrete operands


def _to_float(bits: int, size: int) -> float:
    _check_format(size)
    return struct.unpack(_FORMATS[size], bits.to_bytes(size, "little"))[0]


def _from_float(value: float, size: int) -> int:
    """Round a Python float to the format, and return its encoding."""
    _check_format(size)
    if math.isnan(value):
        return _CANONICAL_NAN[size]
    try:
        packed = struct.pack(_FORMATS[size], value)
    except OverflowError:
        # struct refuses a finite value that rounds to infinity.
        packed = struct.pack(_FORMATS[size], math.copysign(math.inf, value))
    return int.from_bytes(packed, "little")


def _from_int(value: int, size: int) -> int:
    """Round an integer to the format, and return its encoding."""
    _check_format(size)
    if size == 8 or abs(value) < (1 << 53):
        # Either exact in a double, or rounded straight to the target.
        return _from_float(float(value), size)
    # Rounding to double and then to a narrower format could round twice.
    # Keep 30 significant bits and fold the rest into a sticky bit (rounding
    # to odd), which the single rounding to the target then rounds correctly.
    magnitude = abs(value)
    shift = magnitude.bit_length() - 30
    kept = magnitude >> shift
    if magnitude & ((1 << shift) - 1):
        kept |= 1
    return _from_float(math.copysign(math.ldexp(kept, shift), value), size)


def _sign_bit(size: int) -> int:
    _check_format(size)
    return 1 << (size * 8 - 1)


def _signed(value: int, size: int) -> int:
    bits = size * 8
    value &= (1 << bits) - 1
    return value - (1 << bits) if value >> (bits - 1) else value


def _divide(x: float, y: float) -> float:
    if y == 0:
        if x == 0 or math.isnan(x):
            return math.nan
        return math.copysign(math.inf, x) * math.copysign(1.0, y)
    return x / y


def _sqrt(x: float) -> float:
    if x < 0:
        return math.nan
    return math.sqrt(x)


def _trunc(size_out: int, size_in: int, bits: int) -> int:
    x = _to_float(bits, size_in)
    low, high = _int_range(size_out)
    if math.isnan(x):
        value = 0
    elif math.isinf(x):
        value = high if x > 0 else low
    else:
        value = min(max(int(x), low), high)
    return value & ((1 << (size_out * 8)) - 1)


def _to_integral(x: float, integral: typing.Callable[[float], int]) -> float:
    if not math.isfinite(x):
        return x
    result = float(integral(x))
    # ceil(-0.5) and floor(-0.0) are -0.0.
    return math.copysign(0.0, x) if result == 0 else result


def _round(x: float) -> float:
    if not math.isfinite(x):
        return x
    # Exactly, not as floor(x + 0.5) in floating point, which rounds
    # 0.49999999999999994 up. A zero result is +0.0, as in Ghidra.
    return float(math.floor(fractions.Fraction(x) + fractions.Fraction(1, 2)))


# Symbolic operands


def _fp(value: claripy.ast.BV, size: int) -> claripy.ast.FP:
    if size not in _SORTS:
        raise exceptions.EmulationError(
            f"angr cannot reason about symbolic {size * 8}-bit floating point"
        )
    return value.raw_to_fp()


def _bits(value: claripy.ast.FP, size: int) -> claripy.ast.BV:
    """Encode a float, with any NaN as the canonical NaN."""
    return claripy.If(
        claripy.fpIsNaN(value),
        claripy.BVV(_CANONICAL_NAN[size], size * 8),
        claripy.fpToIEEEBV(value),
    )


def _boolean(condition: claripy.ast.Bool, size: int) -> claripy.ast.BV:
    return claripy.If(condition, claripy.BVV(1, size * 8), claripy.BVV(0, size * 8))


def _symbolic_trunc(size_out: int, size_in: int, value: claripy.ast.BV):
    x = _fp(value, size_in)
    bits = size_out * 8
    low, high = _int_range(size_out)
    # -2**(bits - 1), exact in every format.
    bound = claripy.fpToFP(_RNE, claripy.FPV(float(low), _SORTS[8]), x.sort)
    return claripy.If(
        claripy.fpIsNaN(x),
        claripy.BVV(0, bits),
        claripy.If(
            claripy.fpGEQ(x, claripy.fpNeg(bound)),
            claripy.BVV(high, bits),
            claripy.If(
                claripy.fpLT(x, bound),
                claripy.BVV(low & ((1 << bits) - 1), bits),
                claripy.fpToSBV(_RTZ, x, bits),
            ),
        ),
    )


def _symbolic_divide(rm, x: claripy.ast.FP, y: claripy.ast.FP) -> claripy.ast.FP:
    # claripy folds a constant division by zero wrongly: 0/0 and NaN/0 to an
    # infinity, and inf/-0 to +inf. Give those results directly.
    zero = claripy.FPV(0.0, x.sort)
    top = x.sort.length - 1
    negative = claripy.Extract(top, top, claripy.fpToIEEEBV(x)) != claripy.Extract(
        top, top, claripy.fpToIEEEBV(y)
    )
    by_zero = claripy.If(
        claripy.Or(claripy.fpEQ(x, zero), claripy.fpIsNaN(x)),
        claripy.FPV(math.nan, x.sort),
        claripy.If(
            negative, claripy.FPV(-math.inf, x.sort), claripy.FPV(math.inf, x.sort)
        ),
    )
    return claripy.If(claripy.fpEQ(y, zero), by_zero, claripy.fpDiv(rm, x, y))


def _symbolic_int2float(
    size_out: int, size_in: int, value: claripy.ast.BV
) -> claripy.ast.BV:
    sort = _fp_sort(size_out)
    bits = size_in * 8
    direct = claripy.fpToFP(_RNE, value, sort)
    if size_out == 8 or bits <= 53:
        return _bits(direct, size_out)
    # claripy folds a constant conversion through a double, which can round
    # twice, as _from_int describes. Round to odd as _from_int does, so that
    # the integer converted has at most 30 significant bits and is exact in
    # a double.
    negative = claripy.SLT(value, 0)
    magnitude = claripy.If(negative, -value, value)
    result = direct
    for length in range(54, bits + 1):
        shift = length - 30
        kept = claripy.LShR(magnitude, shift)
        sticky = claripy.If(
            claripy.Extract(shift - 1, 0, magnitude) == 0,
            claripy.BVV(0, bits),
            claripy.BVV(1, bits),
        )
        scaled = claripy.fpMul(
            _RNE,
            claripy.fpToFP(_RNE, kept | sticky, sort),
            claripy.FPV(2.0**shift, sort),
        )
        result = claripy.If(
            claripy.Extract(length - 1, length - 1, magnitude) == 1,
            claripy.If(negative, claripy.fpNeg(scaled), scaled),
            result,
        )
    return _bits(result, size_out)


def _symbolic_integral(size: int, value: claripy.ast.BV, kind: str):
    x = _fp(value, size)
    sort = x.sort
    bits = size * 8
    raw = claripy.fpToIEEEBV(x)

    def const(v: float) -> claripy.ast.FP:
        return claripy.fpToFP(_RNE, claripy.FPV(v, _SORTS[8]), sort)

    if kind == "round":
        floor = claripy.fpToSBV(_RTN, x, 64)
        fraction = claripy.fpSub(_RNE, x, claripy.fpToFP(_RNE, floor, sort))
        integer = claripy.If(claripy.fpGEQ(fraction, const(0.5)), floor + 1, floor)
        # A zero result is +0.0.
        zero = claripy.BVV(0, bits)
    else:
        integer = claripy.fpToSBV(_RTP if kind == "ceil" else _RTN, x, 64)
        # A zero result keeps the input's sign.
        zero = claripy.Concat(
            claripy.Extract(bits - 1, bits - 1, raw), claripy.BVV(0, bits - 1)
        )
    rounded = claripy.If(
        integer == 0, zero, claripy.fpToIEEEBV(claripy.fpToFP(_RNE, integer, sort))
    )
    # Infinities, NaNs and floats too large to have a fraction stay as they
    # are; a conversion to a 64-bit integer would not be exact for them.
    already_integral = claripy.Or(
        claripy.fpIsNaN(x),
        claripy.fpIsInf(x),
        claripy.fpGEQ(claripy.fpAbs(x), const(2.0 ** (_PRECISION[size] - 1))),
    )
    return claripy.If(already_integral, _bits(x, size), rounded)


# Behaviors


class _FloatUnary(OpBehavior):
    def __init__(
        self,
        opcode: OpCode,
        concrete: typing.Callable[[int, int, int], int],
        symbolic: typing.Callable[[int, int, claripy.ast.BV], claripy.ast.BV],
    ):
        super().__init__(opcode, True)
        self._concrete = concrete
        self._symbolic = symbolic

    def evaluate_unary(self, size_out: int, size_in: int, in1):
        if in1.concrete:
            result = self._concrete(size_out, size_in, in1.concrete_value)
            return claripy.BVV(result, size_out * 8)
        return self._symbolic(size_out, size_in, in1)


class _FloatBinary(OpBehavior):
    def __init__(
        self,
        opcode: OpCode,
        concrete: typing.Callable[[int, int, int, int], int],
        symbolic: typing.Callable[
            [int, int, claripy.ast.BV, claripy.ast.BV], claripy.ast.BV
        ],
    ):
        super().__init__(opcode, False)
        self._concrete = concrete
        self._symbolic = symbolic

    def evaluate_binary(self, size_out: int, size_in: int, in1, in2):
        if in1.concrete and in2.concrete:
            result = self._concrete(
                size_out, size_in, in1.concrete_value, in2.concrete_value
            )
            return claripy.BVV(result, size_out * 8)
        return self._symbolic(size_out, size_in, in1, in2)


def _arithmetic(
    opcode: OpCode,
    concrete: typing.Callable[[float, float], float],
    symbolic: typing.Callable[..., claripy.ast.FP],
) -> _FloatBinary:
    return _FloatBinary(
        opcode,
        lambda so, si, a, b: _from_float(
            concrete(_to_float(a, si), _to_float(b, si)), so
        ),
        lambda so, si, a, b: _bits(symbolic(_RNE, _fp(a, si), _fp(b, si)), so),
    )


def _comparison(
    opcode: OpCode,
    concrete: typing.Callable[[float, float], bool],
    symbolic: typing.Callable[[claripy.ast.FP, claripy.ast.FP], claripy.ast.Bool],
) -> _FloatBinary:
    return _FloatBinary(
        opcode,
        lambda so, si, a, b: int(concrete(_to_float(a, si), _to_float(b, si))),
        lambda so, si, a, b: _boolean(symbolic(_fp(a, si), _fp(b, si)), so),
    )


def _integral(opcode: OpCode, concrete, kind: str) -> _FloatUnary:
    return _FloatUnary(
        opcode,
        lambda so, si, a: _from_float(concrete(_to_float(a, si)), so),
        lambda so, si, a: _symbolic_integral(si, a, kind),
    )


def _float_behaviors() -> typing.Dict[OpCode, OpBehavior]:
    return {
        OpCode.FLOAT_ADD: _arithmetic(
            OpCode.FLOAT_ADD, lambda x, y: x + y, claripy.fpAdd
        ),
        OpCode.FLOAT_SUB: _arithmetic(
            OpCode.FLOAT_SUB, lambda x, y: x - y, claripy.fpSub
        ),
        OpCode.FLOAT_MULT: _arithmetic(
            OpCode.FLOAT_MULT, lambda x, y: x * y, claripy.fpMul
        ),
        OpCode.FLOAT_DIV: _arithmetic(OpCode.FLOAT_DIV, _divide, _symbolic_divide),
        OpCode.FLOAT_EQUAL: _comparison(
            OpCode.FLOAT_EQUAL, lambda x, y: x == y, claripy.fpEQ
        ),
        OpCode.FLOAT_NOTEQUAL: _comparison(
            OpCode.FLOAT_NOTEQUAL,
            lambda x, y: x != y,
            lambda x, y: claripy.Not(claripy.fpEQ(x, y)),
        ),
        OpCode.FLOAT_LESS: _comparison(
            OpCode.FLOAT_LESS, lambda x, y: x < y, claripy.fpLT
        ),
        OpCode.FLOAT_LESSEQUAL: _comparison(
            OpCode.FLOAT_LESSEQUAL, lambda x, y: x <= y, claripy.fpLEQ
        ),
        OpCode.FLOAT_NAN: _FloatUnary(
            OpCode.FLOAT_NAN,
            lambda so, si, a: int(math.isnan(_to_float(a, si))),
            lambda so, si, a: _boolean(claripy.fpIsNaN(_fp(a, si)), so),
        ),
        OpCode.FLOAT_NEG: _FloatUnary(
            OpCode.FLOAT_NEG,
            lambda so, si, a: a ^ _sign_bit(si),
            lambda so, si, a: a ^ _sign_bit(si),
        ),
        OpCode.FLOAT_ABS: _FloatUnary(
            OpCode.FLOAT_ABS,
            lambda so, si, a: a & (_sign_bit(si) - 1),
            lambda so, si, a: a & (_sign_bit(si) - 1),
        ),
        OpCode.FLOAT_SQRT: _FloatUnary(
            OpCode.FLOAT_SQRT,
            lambda so, si, a: _from_float(_sqrt(_to_float(a, si)), so),
            lambda so, si, a: _bits(claripy.fpSqrt(_RNE, _fp(a, si)), so),
        ),
        OpCode.FLOAT_INT2FLOAT: _FloatUnary(
            OpCode.FLOAT_INT2FLOAT,
            lambda so, si, a: _from_int(_signed(a, si), so),
            _symbolic_int2float,
        ),
        OpCode.FLOAT_FLOAT2FLOAT: _FloatUnary(
            OpCode.FLOAT_FLOAT2FLOAT,
            lambda so, si, a: _from_float(_to_float(a, si), so),
            lambda so, si, a: _bits(claripy.fpToFP(_RNE, _fp(a, si), _fp_sort(so)), so),
        ),
        OpCode.FLOAT_TRUNC: _FloatUnary(
            OpCode.FLOAT_TRUNC,
            _trunc,
            _symbolic_trunc,
        ),
        OpCode.FLOAT_CEIL: _integral(
            OpCode.FLOAT_CEIL, lambda x: _to_integral(x, math.ceil), "ceil"
        ),
        OpCode.FLOAT_FLOOR: _integral(
            OpCode.FLOAT_FLOOR, lambda x: _to_integral(x, math.floor), "floor"
        ),
        OpCode.FLOAT_ROUND: _integral(OpCode.FLOAT_ROUND, _round, "round"),
    }


def _fp_sort(size: int):
    if size not in _SORTS:
        raise exceptions.EmulationError(
            f"angr cannot reason about symbolic {size * 8}-bit floating point"
        )
    return _SORTS[size]


class FloatBehaviorFactory(BehaviorFactory):
    """angr's p-code behaviors, with the floating-point ones implemented."""

    def _register_behaviors(self) -> None:
        super()._register_behaviors()
        self._behaviors.update(_float_behaviors())


FLOAT_BEHAVIORS = FloatBehaviorFactory()


class FloatPcodeEngine(angr.engines.UberEnginePcode):
    """angr's p-code engine, with floating-point operations.

    angr's lifter gives every block its own behaviors, so this engine gives
    each block SmallWorld's before running it.
    """

    def handle_pcode_block(self, irsb) -> None:
        irsb.behaviors = FLOAT_BEHAVIORS
        super().handle_pcode_block(irsb)
