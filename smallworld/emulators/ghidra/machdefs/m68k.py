from ....platforms import Architecture, Byteorder
from .machdef import GhidraMachineDef


class M68KMachineDef(GhidraMachineDef):
    arch = Architecture.M68K
    byteorder = Byteorder.BIG

    # This refers specifically to the 68040.
    language_id = "68000:BE:32:default"

    _registers = {
        "d0": "d0",
        "d1": "d1",
        "d2": "d2",
        "d3": "d3",
        "d4": "d4",
        "d5": "d5",
        "d6": "d6",
        "d7": "d7",
        "a0": "a0",
        "a1": "a1",
        "a2": "a2",
        "a3": "a3",
        "a4": "a4",
        "a5": "a5",
        "a6": "a6",
        "fp": "a6",
        # NOTE: Technically, Ghidra has a separate USP register.
        # Ghidra handles this kind of mutable alias
        # by making the alias a true register, and resetting it when a context switch happens.
        # This is not currently possible to model in SmallWorld.
        # I sincerely doubt Ghidra can model m68k interrupt state, anyway.
        "usp": "sp",
        "a7": "sp",
        "sp": "sp",
        "pc": "pc",
        "fpcr": "fpcr",
        "fpsr": "fpsr",
        "fpiar": "fpiar",
        "fp0": "fp0",
        "fp1": "fp1",
        "fp2": "fp2",
        "fp3": "fp3",
        "fp4": "fp4",
        "fp5": "fp5",
        "fp6": "fp6",
        "fp7": "fp7",
        "isp": "isp",
        "ssp": "isp",
        "msp": "msp",
        # NOTE: Ghidra doesn't expose the status register in a way we can access
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
        # NOTE: Ghidra supports a few extra registers.
        #
        # No idea what these are; I suspect they're from the 68060 or ColdFire,
        # which I didn't research when building the model.
        # I further suspect they're part of the MMU,
        # which I strongly suspect Ghidra doesn't model.
        #
        # "caar": "caar",
        # "ac0": "ac0",
        # "ac1": "ac1",
        # "tt0": "tt0",
        # "tt1": "tt1",
    }
