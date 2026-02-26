from ..... import platforms
from .....exceptions import ConfigurationError
from ..structs import ElfRela
from .rela import ElfRelocator

R_68K_GLOB_DAT = 20
R_68K_JMP_SLOT = 21
R_68K_RELATIVE = 22
R_68K_NUM = 43


class M68KElfRelocator(ElfRelocator):
    arch = platforms.Architecture.M68K
    byteorder = platforms.Byteorder.BIG

    def _compute_value(self, rela: ElfRela, elf):
        if (
            rela.type == R_68K_GLOB_DAT
            or rela.type == R_68K_JMP_SLOT
            or rela.type == R_68K_RELATIVE
        ):
            # Different semantics, all behave the same
            if not rela.is_rela:
                raise ConfigurationError("Using Rels.  Need to be careful")
            addend = rela.addend
            val = rela.symbol.value + rela.symbol.baseaddr + addend
            return val.to_bytes(4, "big")
        elif rela.type >= 0 and rela.type < R_68K_NUM:
            raise ConfigurationError(
                f"Valid, but unsupported relocation for {rela.symbol.name}: {rela.type}"
            )
        else:
            raise ConfigurationError(
                f"Invalid relocation type for {rela.symbol.name}: {rela.type}"
            )
