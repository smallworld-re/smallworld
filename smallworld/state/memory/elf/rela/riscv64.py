from ..... import platforms
from .....exceptions import ConfigurationError
from ..structs import ElfRela
from .rela import ElfRelocator

R_RISCV_64 = 2  #
R_RISCV_JUMP_SLOT = 5  # Create PLT entry
R_RISCV_RELATIVE = 3  # Adjust by program base


class RISCV64ElfRelocator(ElfRelocator):
    arch = platforms.Architecture.RISCV64
    byteorder = platforms.Byteorder.LITTLE

    def _compute_value(self, rela: ElfRela):
        if (
            rela.type == R_RISCV_64
            or rela.type == R_RISCV_JUMP_SLOT
            or rela.type == R_RISCV_RELATIVE
        ):
            # Different semantics, all behave the same
            val = rela.symbol.value + rela.symbol.baseaddr + rela.addend
            return val.to_bytes(8, "little")
        else:
            raise ConfigurationError(
                "Unknown relocation type for {rela.symbol.name}: {rela.type}"
            )
