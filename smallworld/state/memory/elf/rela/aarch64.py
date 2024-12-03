from ..... import platforms
from .....exceptions import ConfigurationError
from ..structs import ElfRela
from .rela import ElfRelocator

R_AARCH64_GLOB_DAT = 1025  # Create GOT entry
R_AARCH64_JUMP_SLOT = 1026  # Create PLT entry
R_AARCH64_RELATIVE = 1027  # Adjust by program base


class AArch64ElfRelocator(ElfRelocator):
    arch = platforms.Architecture.AARCH64
    byteorder = platforms.Byteorder.LITTLE

    def _compute_value(self, rela: ElfRela):
        if (
            rela.type == R_AARCH64_GLOB_DAT
            or rela.type == R_AARCH64_JUMP_SLOT
            or rela.type == R_AARCH64_RELATIVE
        ):
            # Different semantics, all behave the same
            val = rela.symbol.value + rela.symbol.baseaddr + rela.addend
            return val.to_bytes(8, "little")
        else:
            raise ConfigurationError(
                "Unknown relocation type for {rela.symbol.name}: {rela.type}"
            )
