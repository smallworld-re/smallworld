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

    def _compute_value(self, rela: ElfRela, elf):
        if (
            rela.type == R_RISCV_64
            or rela.type == R_RISCV_JUMP_SLOT
            or rela.type == R_RISCV_RELATIVE
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
                "Unknown relocation type for {rela.symbol.name}: {rela.type}"
            )
