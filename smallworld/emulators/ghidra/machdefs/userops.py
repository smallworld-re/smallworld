"""Userops SmallWorld runs itself, for SLEIGH that calls a userop Ghidra's
emulator doesn't implement.

Each takes the emulator, the instruction's mnemonic and the userop's arguments
as unsigned integers, and returns its output's value, or None for a userop with
no output. See ``GhidraMachineDef.userops``.
"""

import fractions
import math
import struct
import typing

from .... import exceptions

# Reflected CRC-32 and CRC-32C (Castagnoli) polynomials.
_CRC32_POLY = 0xEDB88320
_CRC32C_POLY = 0x82F63B78

_CRC32_SIZES = {"b": 1, "h": 2, "w": 4}


def crc32_calc(emu: typing.Any, mnemonic: str, args: typing.Sequence[int]) -> int:
    """``Crc32Calc(acc, value)``, for ARM's crc32 and crc32c instructions.

    The userop's arguments don't say which polynomial or how many bytes of
    the value to fold in, so this reads them from the mnemonic: ``crc32`` or
    ``crc32c``, then ``b``, ``h`` or ``w``.
    """
    acc, value = args
    poly = _CRC32C_POLY if mnemonic.startswith("crc32c") else _CRC32_POLY
    size = _CRC32_SIZES[mnemonic[-1]]
    # The architecture folds the value's low byte in first, with no initial
    # or final inversion.
    for byte in (value & ((1 << (size * 8)) - 1)).to_bytes(size, "little"):
        acc ^= byte
        for _ in range(8):
            acc = (acc >> 1) ^ (poly if acc & 1 else 0)
    return acc


def _signed(value: int, bits: int) -> int:
    return value - (1 << bits) if value >> (bits - 1) else value


def neon_sqrdml_as_h(emu: typing.Any, mnemonic: str, args: typing.Sequence[int]) -> int:
    """``NEON_sqrdml_as_h(vd, vn, vm, esize, elements, subop[, index])``, for
    AArch64's sqrdmlah and sqrdmlsh.

    Each element of ``vd`` becomes the saturated, rounded high half of
    ``vd << esize`` plus (subop 0) or minus (subop 1) twice the product of the
    ``vn`` and ``vm`` elements, taking ``vm``'s element ``index`` when given.
    Elements past ``elements`` are zeroed. Ghidra models no FPSR, so this can't
    set FPSR.QC on saturation.
    """
    vd, vn, vm, esize, elements, subop = args[:6]
    index = args[6] if len(args) > 6 else None
    mask = (1 << esize) - 1
    low, high = -(1 << (esize - 1)), (1 << (esize - 1)) - 1

    def element(vector: int, e: int) -> int:
        return _signed((vector >> (e * esize)) & mask, esize)

    result = 0
    for e in range(elements):
        product = 2 * element(vn, e) * element(vm, e if index is None else index)
        if subop:
            product = -product
        accum = (element(vd, e) << esize) + product + (1 << (esize - 1))
        result |= (max(low, min(high, accum >> esize)) & mask) << (e * esize)
    return result


def _set_stack_limit(register: str):
    def userop(emu: typing.Any, mnemonic: str, args: typing.Sequence[int]) -> None:
        # Bits [2:0] of the stack-limit registers are RES0.
        emu.write_register_content(register, args[0] & ~0x7 & 0xFFFFFFFF)
        return None

    return userop


def _get_stack_limit(register: str):
    def userop(emu: typing.Any, mnemonic: str, args: typing.Sequence[int]) -> int:
        return emu.read_register_content(register)

    return userop


# ARM's FPRounding values, which SLEIGH passes to the rounding userops.
_ROUND_TIEEVEN, _ROUND_POSINF, _ROUND_NEGINF, _ROUND_ZERO, _ROUND_TIEAWAY = range(5)

# (format, quiet-NaN bit, default NaN) by element size.
_FP_ELEMENTS = {
    16: ("e", 1 << 9, 0x7E00),
    32: ("f", 1 << 22, 0x7FC00000),
    64: ("d", 1 << 51, 0x7FF8000000000000),
}


def _fp_value(bits: int, esize: int) -> float:
    fmt = _FP_ELEMENTS[esize][0]
    return struct.unpack(f"<{fmt}", bits.to_bytes(esize // 8, "little"))[0]


def _fp_bits(value: float, esize: int) -> int:
    fmt = _FP_ELEMENTS[esize][0]
    return int.from_bytes(struct.pack(f"<{fmt}", value), "little")


# Exponent masks of the formats flush-to-zero mode applies to.
_FP_EXPONENTS = {32: 0xFF << 23, 64: 0x7FF << 52}


def _flush(bits: int, esize: int, flush_to_zero: bool) -> int:
    """A denormal input as flush-to-zero mode reads it: a zero of the same
    sign. Half precision has its own control, FPSCR.FZ16, which this leaves
    off."""
    if not flush_to_zero or esize not in _FP_EXPONENTS:
        return bits
    if bits & _FP_EXPONENTS[esize]:
        return bits
    return bits & (1 << (esize - 1))


def _scalar_flush_to_zero(emu: typing.Any) -> bool:
    """FPSCR.FZ, which the scalar instructions follow. Advanced SIMD always
    flushes."""
    return bool((emu.read_register_content("fpscr") >> 24) & 1)


def _round(value: float, rounding: int) -> int:
    """Round a finite value to an integer, as an FPRounding value says."""
    exact = fractions.Fraction(value)
    if rounding == _ROUND_TIEEVEN:
        return round(exact)
    if rounding == _ROUND_POSINF:
        return math.ceil(exact)
    if rounding == _ROUND_NEGINF:
        return math.floor(exact)
    if rounding == _ROUND_ZERO:
        return math.trunc(exact)
    if rounding == _ROUND_TIEAWAY:
        magnitude = math.floor(abs(exact) + fractions.Fraction(1, 2))
        return -magnitude if exact < 0 else magnitude
    raise ValueError(f"unsupported FP rounding {rounding}")


def _round_int(bits: int, esize: int, rounding: int, flush_to_zero: bool) -> int:
    """FPRoundInt: round to an integral value in the same format. Keeps the
    sign of a zero result, and quiets a signalling NaN."""
    bits = _flush(bits, esize, flush_to_zero)
    value = _fp_value(bits, esize)
    if math.isnan(value):
        return bits | _FP_ELEMENTS[esize][1]
    if math.isinf(value) or value == 0:
        return bits
    return _fp_bits(math.copysign(_round(value, rounding), value), esize)


def _fp_to_fixed(
    bits: int,
    esize: int,
    rounding: int,
    isize: int,
    signed: bool,
    flush_to_zero: bool,
) -> int:
    """FPToFixed with no fraction bits: round to a saturated integer of
    ``isize`` bits, NaN giving 0."""
    value = _fp_value(_flush(bits, esize, flush_to_zero), esize)
    if signed:
        low, high = -(1 << (isize - 1)), (1 << (isize - 1)) - 1
    else:
        low, high = 0, (1 << isize) - 1
    if math.isnan(value):
        return 0
    if math.isinf(value):
        integer = high if value > 0 else low
    else:
        integer = max(low, min(high, _round(value, rounding)))
    return integer & ((1 << isize) - 1)


def _lanewise(width: int, esize: int, function, *operands: int) -> int:
    """Apply ``function`` to each ``esize``-bit lane of ``width``-bit
    operands, and pack the results."""
    mask = (1 << esize) - 1
    result = 0
    for shift in range(0, width, esize):
        result |= function(*((x >> shift) & mask for x in operands)) << shift
    return result


def _arm_fp_instruction(emu: typing.Any) -> int:
    """The ARM or Thumb instruction being executed, as one word in ARM's
    field layout: an ARM instruction is one little-endian word, and a Thumb
    one two little-endian halfwords, the first most significant."""
    data = emu.current_instruction_bytes()
    if not emu.read_sleigh_register("TMode"):
        return int.from_bytes(data, "little")
    return (int.from_bytes(data[0:2], "little") << 16) | int.from_bytes(
        data[2:4], "little"
    )


def _field(insn: int, high: int, low: int) -> int:
    return (insn >> low) & ((1 << (high - low + 1)) - 1)


def _unsupported(emu: typing.Any, mnemonic: str, insn: int) -> Exception:
    return exceptions.EmulationExecFailure(
        f"{mnemonic} {insn:#010x} isn't an instruction SmallWorld implements for "
        "this Ghidra userop",
        emu.read_register_content("pc"),
    )


# vrint{a,n,p,m}'s rounding field: ties away, ties to even, up, down.
_VRINT_RM = (_ROUND_TIEAWAY, _ROUND_TIEEVEN, _ROUND_POSINF, _ROUND_NEGINF)


def _scalar_registers(insn: int):
    """The Dd, Dn, Dm or Sd, Sn, Sm of a scalar FP instruction, by its size
    field, and their size."""
    wide = _field(insn, 9, 8) == 0b11

    def register(vector: int, extra: int) -> str:
        return f"d{(extra << 4) | vector}" if wide else f"s{(vector << 1) | extra}"

    return (
        register(_field(insn, 15, 12), _field(insn, 22, 22)),
        register(_field(insn, 19, 16), _field(insn, 7, 7)),
        register(_field(insn, 3, 0), _field(insn, 5, 5)),
        64 if wide else 32,
    )


def coprocessor_function2(
    emu: typing.Any, mnemonic: str, args: typing.Sequence[int]
) -> None:
    """``coprocessor_function2(...)``, for ARMv8's vsel and scalar
    vrint{a,n,p,m}.

    Ghidra's ARMv8 language decodes these as the cdp2 they share an encoding
    space with, so the userop's arguments are cdp2's coprocessor fields. This
    decodes the instruction instead, and reads and writes its registers
    itself. Sets no FPSCR exception flags.
    """
    insn = _arm_fp_instruction(emu)
    if (
        _field(insn, 31, 24) != 0xFE
        or _field(insn, 11, 10) != 0b10
        or _field(insn, 9, 8) not in (0b10, 0b11)
        or _field(insn, 4, 4) != 0
    ):
        raise _unsupported(emu, mnemonic, insn)
    d, n, m, esize = _scalar_registers(insn)
    if _field(insn, 23, 23) == 0 and _field(insn, 6, 6) == 0:
        # vsel<cc>: Dd or Sd takes n when the condition holds, else m.
        cpsr = emu.read_register_content("cpsr")
        ng, zr, ov = (cpsr >> 31) & 1, (cpsr >> 30) & 1, (cpsr >> 28) & 1
        holds = (zr, ov, ng == ov, not zr and ng == ov)[_field(insn, 21, 20)]
        emu.write_register_content(d, emu.read_register_content(n if holds else m))
    elif (
        _field(insn, 23, 23) == 1
        and _field(insn, 21, 18) == 0b1110
        and _field(insn, 7, 6) == 0b01
    ):
        # vrint<rm>
        rounding = _VRINT_RM[_field(insn, 17, 16)]
        emu.write_register_content(
            d,
            _round_int(
                emu.read_register_content(m),
                esize,
                rounding,
                _scalar_flush_to_zero(emu),
            ),
        )
    else:
        raise _unsupported(emu, mnemonic, insn)
    return None


def coprocessor_function(
    emu: typing.Any, mnemonic: str, args: typing.Sequence[int]
) -> None:
    """``coprocessor_function(...)``, for ARMv8's scalar vrint{r,z,x}.

    Ghidra's ARMv8 language decodes these as cdp; see `coprocessor_function2`.
    vrintr and vrintx round as FPSCR.RMode says, and vrintz towards zero.
    vrintx's inexact exception isn't raised.
    """
    insn = _arm_fp_instruction(emu)
    if (
        _field(insn, 27, 23) != 0b11101
        or _field(insn, 21, 17) != 0b11011
        or _field(insn, 11, 10) != 0b10
        or _field(insn, 9, 8) not in (0b10, 0b11)
        or _field(insn, 6, 6) != 1
        or _field(insn, 4, 4) != 0
    ):
        raise _unsupported(emu, mnemonic, insn)
    if _field(insn, 16, 16) == 0 and _field(insn, 7, 7) == 1:
        rounding = _ROUND_ZERO
    else:
        rounding = (emu.read_register_content("fpscr") >> 22) & 0b11
    d, _, m, esize = _scalar_registers(insn)
    emu.write_register_content(
        d,
        _round_int(
            emu.read_register_content(m),
            esize,
            rounding,
            _scalar_flush_to_zero(emu),
        ),
    )
    return None


def _float_to_round(signed: bool):
    def userop(emu: typing.Any, mnemonic: str, args: typing.Sequence[int]) -> int:
        # The operand's size isn't in the arguments; it's the size field.
        insn = _arm_fp_instruction(emu)
        esize = {0b01: 16, 0b10: 32, 0b11: 64}.get(_field(insn, 9, 8))
        if esize is None:
            raise _unsupported(emu, mnemonic, insn)
        value, rounding = args
        return _fp_to_fixed(
            value & ((1 << esize) - 1),
            esize,
            rounding,
            32,
            signed,
            _scalar_flush_to_zero(emu),
        )

    return userop


float_to_signed_round = _float_to_round(True)
"""``FloatToSignedRound(value, rounding)``, for ARMv8's scalar
vcvt{a,n,p,m}.s32: round to a saturated signed 32-bit integer."""

float_to_unsigned_round = _float_to_round(False)
"""``FloatToUnsignedRound(value, rounding)``, for ARMv8's scalar
vcvt{a,n,p,m}.u32."""


def _vector_float_to_round(signed: bool):
    def userop(emu: typing.Any, mnemonic: str, args: typing.Sequence[int]) -> int:
        value, single, rounding = args
        esize = 32 if single else 16
        # A D or Q register, by the instruction's Q bit.
        width = 128 if _field(_arm_fp_instruction(emu), 6, 6) else 64
        return _lanewise(
            width,
            esize,
            lambda lane: _fp_to_fixed(lane, esize, rounding, esize, signed, True),
            value,
        )

    return userop


vector_float_to_signed_round = _vector_float_to_round(True)
"""``VectorFloatToSignedRound(value, single, rounding)``, for ARMv8's
Advanced SIMD vcvt{a,n,p,m}.s32.f32 and .s16.f16: each lane rounded to a
saturated signed integer of its own size."""

vector_float_to_unsigned_round = _vector_float_to_round(False)
"""``VectorFloatToUnsignedRound(value, single, rounding)``, for ARMv8's
Advanced SIMD vcvt{a,n,p,m}.u32.f32 and .u16.f16."""


def _fp_min_max_num(maximum: bool):
    def userop(emu: typing.Any, mnemonic: str, args: typing.Sequence[int]) -> int:
        insn = _arm_fp_instruction(emu)
        if _field(insn, 27, 23) == 0b11101:
            # Floating point: one element, of the size field's size.
            esize = {0b01: 16, 0b10: 32, 0b11: 64}[_field(insn, 9, 8)]
            width = max(esize, 32)
            # Default NaN and flush-to-zero modes are FPSCR.DN and FZ.
            default_nan = bool((emu.read_register_content("fpscr") >> 25) & 1)
            flush_to_zero = _scalar_flush_to_zero(emu)
        else:
            # Advanced SIMD: a D or Q register of f32 or f16 lanes, which
            # always uses the default NaN and flushes denormals.
            esize = 16 if _field(insn, 20, 20) else 32
            width = 128 if _field(insn, 6, 6) else 64
            default_nan = flush_to_zero = True
        _, quiet, dnan = _FP_ELEMENTS[esize]

        def lane(a: int, b: int) -> int:
            a, b = _flush(a, esize, flush_to_zero), _flush(b, esize, flush_to_zero)
            va, vb = _fp_value(a, esize), _fp_value(b, esize)
            a_nan, b_nan = math.isnan(va), math.isnan(vb)
            # A quiet NaN loses to a number.
            if a_nan and not b_nan and a & quiet:
                return b
            if b_nan and not a_nan and b & quiet:
                return a
            if a_nan or b_nan:
                if default_nan:
                    return dnan
                # A signalling NaN, quieted, wins over a quiet one, and the
                # first operand over the second.
                nans = [x for x in (a, b) if math.isnan(_fp_value(x, esize))]
                signalling = [x for x in nans if not x & quiet]
                return (signalling or nans)[0] | quiet
            if va == vb:
                # Equal numbers have equal bits, except zeros of opposite
                # sign, whose maximum is +0 and minimum -0.
                return (a & b) if maximum else (a | b)
            return a if (va > vb) == maximum else b

        return _lanewise(width, esize, lane, args[0], args[1])

    return userop


fp_max_num = _fp_min_max_num(True)
"""``FPMaxNum(n, m)``, for ARMv8's vmaxnm: the IEEE 754-2008 maxNum of each
element, where a number beats a quiet NaN and +0 beats -0. Sets no FPSCR
exception flags."""

fp_min_num = _fp_min_max_num(False)
"""``FPMinNum(n, m)``, for ARMv8's vminnm: the minNum counterpart of
`fp_max_num`."""


set_main_stack_pointer_limit = _set_stack_limit("msplim")
"""``setMainStackPointerLimit(value)``, for ARMv8-M's ``msr msplim``."""

set_proc_stack_pointer_limit = _set_stack_limit("psplim")
"""``setProcStackPointerLimit(value)``, for ARMv8-M's ``msr psplim``."""

get_main_stack_pointer_limit = _get_stack_limit("msplim")
"""``getMainStackPointerLimit()``, for ARMv8-M's ``mrs msplim``."""

get_process_stack_pointer_limit = _get_stack_limit("psplim")
"""``getProcessStackPointerLimit()``, for ARMv8-M's ``mrs psplim``."""
