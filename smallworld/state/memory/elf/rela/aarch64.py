from ..... import platforms
from .....exceptions import ConfigurationError
from ..structs import ElfRela
from .rela import ElfRelocator

R_AARCH64_ABS64 = 257  # Direct 64-bit
R_AARCH64_GLOB_DAT = 1025  # Create GOT entry
R_AARCH64_JUMP_SLOT = 1026  # Create PLT entry
R_AARCH64_RELATIVE = 1027  # Adjust by program base


class AArch64ElfRelocator(ElfRelocator):
    arch = platforms.Architecture.AARCH64
    byteorder = platforms.Byteorder.LITTLE

    def _compute_value(self, rela: ElfRela, elf):
        if (
            rela.type == R_AARCH64_GLOB_DAT
            or rela.type == R_AARCH64_JUMP_SLOT
            or rela.type == R_AARCH64_RELATIVE
            or rela.type == R_AARCH64_ABS64
        ):
            if rela.is_rela:
                addend = rela.addend
            else:
                addend = elf.read_int(rela.offset, 8, self.byteorder)

            # Different semantics, all behave the same
            val = rela.symbol.value + rela.symbol.baseaddr + addend
            return val.to_bytes(8, "little")
        else:
            raise ConfigurationError(
                f"Unknown relocation type for {rela.symbol.name}: {hex(rela.type)}"
            )
