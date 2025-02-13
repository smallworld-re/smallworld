from ..... import platforms
from .....exceptions import ConfigurationError
from ..structs import ElfRela
from .rela import ElfRelocator

R_386_GLOB_DAT = 6  # Create GOT entry
R_386_JUMP_SLOT = 7  # Create PLT entry
R_386_RELATIVE = 8  # Adjust by program base
R_386_NUM = 44  # This and higher aren't valid


class I386ElfRelocator(ElfRelocator):
    arch = platforms.Architecture.X86_32
    byteorder = platforms.Byteorder.LITTLE

    def _compute_value(self, rela: ElfRela):
        if (
            rela.type == R_386_GLOB_DAT
            or rela.type == R_386_JUMP_SLOT
            or rela.type == R_386_RELATIVE
        ):
            # Different semantics, all behave the same
            val = rela.symbol.value + rela.symbol.baseaddr + rela.addend
            return val.to_bytes(4, "little")
        elif rela.type >= 0 and rela.type < R_386_NUM:
            raise ConfigurationError(
                "Valid, but unsupported relocation for {rela.symbol.name}: {rela.type}"
            )
        else:
            raise ConfigurationError(
                "Invalid relocation type for {rela.symbol.name}: {rela.type}"
            )
