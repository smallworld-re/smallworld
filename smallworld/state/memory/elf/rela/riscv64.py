from ..... import platforms
from .....exceptions import ConfigurationError
from ..structs import ElfRela
from .rela import ElfRelocator

# ABI shorthand used in the comments below:
#   A: addend
#   B: base address where the image was loaded
#   S: resolved symbol value
R_RISCV_64 = 2  # Write S + A as a 64-bit absolute value.
R_RISCV_RELATIVE = 3  # Write B + A; ignores the symbol value.
R_RISCV_JUMP_SLOT = 5  # Populate a PLT/GOT resolver slot with S + A.


class RISCV64ElfRelocator(ElfRelocator):
    arch = platforms.Architecture.RISCV64
    byteorder = platforms.Byteorder.LITTLE

    def _compute_value(self, rela: ElfRela, elf):
        if rela.type == R_RISCV_64 or rela.type == R_RISCV_JUMP_SLOT:
            if rela.is_rela:
                addend = rela.addend
            else:
                addend = elf.read_int(rela.offset, 8, self.byteorder)

            # Different semantics, all behave the same
            val = rela.symbol.value + rela.symbol.baseaddr + addend
            return val.to_bytes(8, "little")
        elif rela.type == R_RISCV_RELATIVE:
            if rela.is_rela:
                addend = rela.addend
            else:
                addend = elf.read_int(rela.offset, 8, self.byteorder)

            val = elf.address + addend
            return val.to_bytes(8, "little")
        else:
            raise ConfigurationError(
                f"Unknown relocation type for {rela.symbol.name}: {rela.type}"
            )
