from ..... import platforms
from .....exceptions import ConfigurationError
from ..structs import ElfRela
from .rela import ElfRelocator

# ABI shorthand used in the comments below:
#   A: addend
#   B: base address where the image was loaded
#   S: resolved symbol value
R_LARCH_64 = 2  # Write S + A as a 64-bit absolute value.
R_LARCH_RELATIVE = 3  # Write B + A; ignores the symbol value.
R_LARCH_COPY = 4  # Copy the symbol's runtime data bytes into the target.
R_LARCH_JUMP_SLOT = 5  # Populate a PLT/GOT resolver slot with S + A.
R_LARCH_NUM = 127  # This and higher aren't valid


class LoongArch64ElfRelocator(ElfRelocator):
    arch = platforms.Architecture.LOONGARCH64
    byteorder = platforms.Byteorder.LITTLE

    def _compute_value(self, rela: ElfRela, elf):
        if rela.type == R_LARCH_JUMP_SLOT or rela.type == R_LARCH_64:
            # Different semantics, all behave the same
            if rela.is_rela:
                addend = rela.addend
            else:
                addend = elf.read_int(rela.offset, 8, self.byteorder)

            val = rela.symbol.value + rela.symbol.baseaddr + addend
            return val.to_bytes(8, "little")
        elif rela.type == R_LARCH_RELATIVE:
            if rela.is_rela:
                addend = rela.addend
            else:
                addend = elf.read_int(rela.offset, 8, self.byteorder)

            val = elf.address + addend
            return val.to_bytes(8, "little")
        elif rela.type >= 0 and rela.type < R_LARCH_NUM:
            raise ConfigurationError(
                f"Valid, but unsupported relocation for {rela.symbol.name}: {rela.type}"
            )
        else:
            raise ConfigurationError(
                f"Invalid relocation type for {rela.symbol.name}: {rela.type}"
            )
