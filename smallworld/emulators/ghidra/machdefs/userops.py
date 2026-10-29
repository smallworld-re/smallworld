"""Userops SmallWorld runs itself, for SLEIGH that calls a userop Ghidra's
emulator doesn't implement.

Each takes the emulator, the instruction's mnemonic and the userop's arguments
as unsigned integers, and returns its output's value, or None for a userop with
no output. See ``GhidraMachineDef.userops``.
"""

import typing

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


set_main_stack_pointer_limit = _set_stack_limit("msplim")
"""``setMainStackPointerLimit(value)``, for ARMv8-M's ``msr msplim``."""

set_proc_stack_pointer_limit = _set_stack_limit("psplim")
"""``setProcStackPointerLimit(value)``, for ARMv8-M's ``msr psplim``."""

get_main_stack_pointer_limit = _get_stack_limit("msplim")
"""``getMainStackPointerLimit()``, for ARMv8-M's ``mrs msplim``."""

get_process_stack_pointer_limit = _get_stack_limit("psplim")
"""``getProcessStackPointerLimit()``, for ARMv8-M's ``mrs psplim``."""
