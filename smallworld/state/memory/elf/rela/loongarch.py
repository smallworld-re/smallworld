from ..... import platforms
from .....exceptions import ConfigurationError
from ..structs import ElfRela
from .rela import ElfRelocator

R_LARCH_64 = 2  # Direct 64-bit
R_LARCH_RELATIVE = 4  # Adjust by program base
R_LARCH_JUMP_SLOT = 5  # Create PLT entry
R_LARCH_NUM = 127  # This and higher aren't valid


class LoongArch64ElfRelocator(ElfRelocator):
    arch = platforms.Architecture.LOONGARCH64
    byteorder = platforms.Byteorder.LITTLE

    def _compute_value(self, rela: ElfRela):
        if (
            rela.type == R_LARCH_JUMP_SLOT
            or rela.type == R_LARCH_RELATIVE
            or rela.type == R_LARCH_64
        ):
            # Different semantics, all behave the same
            val = rela.symbol.value + rela.symbol.baseaddr + rela.addend
            return val.to_bytes(8, "little")
        elif rela.type >= 0 and rela.type < R_LARCH_NUM:
            raise ConfigurationError(
                f"Valid, but unsupported relocation for {rela.symbol.name}: {rela.type}"
            )
        else:
            raise ConfigurationError(
                f"Invalid relocation type for {rela.symbol.name}: {rela.type}"
            )
