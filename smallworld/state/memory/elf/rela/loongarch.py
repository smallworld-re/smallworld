from ..... import platforms
from .....exceptions import ConfigurationError
from ..structs import ElfRela
from .rela import ElfRelocator

# ABI shorthand used in the comments below:
#   A: addend
#   B: base address where the image was loaded
#   S: resolved symbol value
R_LARCH_32 = 1  # Write S + A as a 32-bit absolute value.
R_LARCH_64 = 2  # Write S + A as a 64-bit absolute value.
R_LARCH_RELATIVE = 3  # Write B + A; ignores the symbol value.
R_LARCH_COPY = 4  # Copy the symbol's runtime data bytes into the target.
R_LARCH_JUMP_SLOT = 5  # Populate a PLT/GOT resolver slot with S + A.
R_LARCH_NUM = 127  # This and higher aren't valid


class LoongArch64ElfRelocator(ElfRelocator):
    supported_platforms = frozenset(
        {
            platforms.Platform(
                platforms.Architecture.LOONGARCH64, platforms.Byteorder.LITTLE
            )
        }
    )

    # The pointer width, and the absolute relocation of that width.
    _word = 8
    _absolute = R_LARCH_64

    def _compute_value(self, rela: ElfRela, elf):
        word = self._word
        mask = (1 << (word * 8)) - 1
        if rela.type == R_LARCH_JUMP_SLOT or rela.type == self._absolute:
            # Different semantics, all behave the same
            if rela.is_rela:
                addend = rela.addend
            else:
                addend = elf.read_int(rela.offset, word, self.byteorder)

            val = rela.symbol.value + rela.symbol.baseaddr + addend
            # Mask to the output width: RELA addends are signed and address
            # sums can wrap, so to_bytes would OverflowError on a raw value.
            return (val & mask).to_bytes(word, "little")
        elif rela.type == R_LARCH_RELATIVE:
            if rela.is_rela:
                addend = rela.addend
            else:
                addend = elf.read_int(rela.offset, word, self.byteorder)

            val = elf.address + addend
            # Mask to the output width: RELA addends are signed and address
            # sums can wrap, so to_bytes would OverflowError on a raw value.
            return (val & mask).to_bytes(word, "little")
        elif rela.type >= 0 and rela.type < R_LARCH_NUM:
            raise ConfigurationError(
                f"Valid, but unsupported relocation for {rela.symbol.name}: {rela.type}"
            )
        else:
            raise ConfigurationError(
                f"Invalid relocation type for {rela.symbol.name}: {rela.type}"
            )


class LoongArch32ElfRelocator(LoongArch64ElfRelocator):
    supported_platforms = frozenset(
        {
            platforms.Platform(
                platforms.Architecture.LOONGARCH32, platforms.Byteorder.LITTLE
            )
        }
    )

    _word = 4
    _absolute = R_LARCH_32
