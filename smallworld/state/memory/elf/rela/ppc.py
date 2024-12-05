from ..... import platforms
from .....exceptions import ConfigurationError
from ..structs import ElfRela
from .rela import ElfRelocator

R_PPC_GLOB_DAT = 20  # Create GOT entry
R_PPC_JUMP_SLOT = 21  # Create PLT entry
R_PPC_RELATIVE = 22  # Adjust by program base


class PowerPCElfRelocator(ElfRelocator):
    arch = platforms.Architecture.POWERPC32
    byteorder = platforms.Byteorder.BIG

    def _compute_value(self, rela: ElfRela):
        if (
            rela.type == R_PPC_GLOB_DAT
            or rela.type == R_PPC_JUMP_SLOT
            or rela.type == R_PPC_RELATIVE
        ):
            # Different semantics, all behave the same
            val = rela.symbol.value + rela.symbol.baseaddr + rela.addend
            return val.to_bytes(4, "big")
        else:
            raise ConfigurationError(
                "Invalid relocation type for {rela.symbol.name}: {rela.type}"
            )
