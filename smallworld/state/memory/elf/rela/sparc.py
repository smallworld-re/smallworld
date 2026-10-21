from ..... import platforms
from .....exceptions import ConfigurationError
from ..structs import ElfRela
from .rela import ElfRelocator

R_SPARC_32 = 3
R_SPARC_GLOB_DAT = 20
R_SPARC_JMP_SLOT = 21
R_SPARC_RELATIVE = 22
R_SPARC_UA32 = 23
R_SPARC_NUM = 253


class SPARC32ElfRelocator(ElfRelocator):
    arch = platforms.Architecture.SPARC32
    byteorder = platforms.Byteorder.BIG

    def _compute_value(self, rela: ElfRela, elf):
        if rela.type in (R_SPARC_32, R_SPARC_GLOB_DAT, R_SPARC_UA32):
            # S + A, a plain 32-bit word.
            if not rela.is_rela:
                raise ConfigurationError("Using Rels.  Need to be careful")
            val = rela.symbol.value + rela.symbol.baseaddr + rela.addend
            return (val & 0xFFFFFFFF).to_bytes(4, "big")
        elif rela.type == R_SPARC_RELATIVE:
            # B + A
            if not rela.is_rela:
                raise ConfigurationError("Using Rels.  Need to be careful")
            val = elf.address + rela.addend
            return (val & 0xFFFFFFFF).to_bytes(4, "big")
        elif rela.type >= 0 and rela.type < R_SPARC_NUM:
            # R_SPARC_JMP_SLOT on 32-bit SPARC rewrites the PLT entry's
            # instructions rather than storing an address, so it is not a
            # value this relocator can produce.
            raise ConfigurationError(
                f"Valid, but unsupported relocation for {rela.symbol.name}: {rela.type}"
            )
        else:
            raise ConfigurationError(
                f"Invalid relocation type for {rela.symbol.name}: {rela.type}"
            )
