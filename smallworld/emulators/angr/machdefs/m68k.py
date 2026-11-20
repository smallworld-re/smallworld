import typing

import angr

from ....platforms import Architecture, Byteorder
from .machdef import GhidraMachineDef
from .pcode_rewrite import pcode_arch

M68K_PCODE_LANGUAGE = "68000:BE:32:default"


class M68KMachineDef(GhidraMachineDef):
    """angr machine definition for the m68k (68040), using Ghidra's p-code.

    The register names are the Ghidra machine definition's, since both run
    the same sleigh language, but this one also narrows sfc, dfc and tc to
    their real widths; see `angr_reg`.
    """

    arch = Architecture.M68K
    byteorder = Byteorder.BIG
    pcode_language = M68K_PCODE_LANGUAGE

    # cas and cas2 branch within their own p-code.
    refuse_pcode_relative_branches = True

    _registers: typing.Dict[str, typing.Optional[str]] = {  # type: ignore[assignment]
        **{f"d{i}": f"d{i}" for i in range(0, 8)},
        **{f"a{i}": f"a{i}" for i in range(0, 7)},
        "fp": "a6",
        # NOTE: Sleigh has separate USP, ISP and MSP registers, but ordinary
        # instructions only use SP, so usp is SP, as in the Ghidra machine
        # definition.
        "usp": "sp",
        "a7": "sp",
        "sp": "sp",
        "pc": "pc",
        "fpcr": "fpcr",
        "fpsr": "fpsr",
        "fpiar": "fpiar",
        **{f"fp{i}": f"fp{i}" for i in range(0, 8)},
        "isp": "isp",
        "ssp": "isp",
        "msp": "msp",
        # NOTE: Sleigh keeps the condition codes in separate flag registers,
        # and only syncs `sr` with them inside instructions that read or
        # write it, so its stored value is stale; neither it nor `ccr` is
        # exposed.
        "sr": None,
        "ccr": None,
        "vbr": "vbr",
        "cacr": "cacr",
        "urp": "urp",
        "srp": "srp",
        "sfc": "sfc",
        "dfc": "dfc",
        "tc": "tc",
        "dtt0": "dtt0",
        "dtt1": "dtt1",
        "itt0": "itt0",
        "itt1": "itt1",
        "mmusr": "mmusr",
    }

    # Control registers that sleigh widens to 4 bytes, by their real sizes.
    # Sleigh still reads all 4 bytes (`movec sfc,d0`), and SmallWorld only
    # sets the low ones, so on angr such a read is partly symbolic.
    _narrow_registers = {"sfc": 1, "dfc": 1, "tc": 2}

    def angr_reg(self, name: str) -> typing.Tuple[int, int]:
        offset, size = super().angr_reg(name)
        if name in self._narrow_registers:
            # The register file is big-endian, so the low-order bytes come
            # last.
            narrow = self._narrow_registers[name]
            return offset + size - narrow, narrow
        return offset, size


class SimCCM68K(angr.calling_conventions.SimCC):
    """m68k System V calling convention.

    Arguments are all passed on the stack, above the return address that
    `jsr`/`bsr` pushes, and integers come back in %d0.

    angr only uses this to return from function hooks; models read their
    arguments and write their results through `M68KSysVCallingContext`,
    which also handles 64-bit (%d0:%d1) and pointer (%a0) returns.
    """

    ARG_REGS: typing.List[str] = []
    FP_ARG_REGS: typing.List[str] = []
    STACKARG_SP_DIFF = 4
    RETURN_VAL = angr.calling_conventions.SimRegArg("d0", 4)
    RETURN_ADDR = angr.calling_conventions.SimStackArg(0, 4)
    ARCH = pcode_arch(M68K_PCODE_LANGUAGE)  # type: ignore


angr.calling_conventions.register_default_cc(M68K_PCODE_LANGUAGE, SimCCM68K)
