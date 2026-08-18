from ..... import platforms
from .....exceptions import ConfigurationError
from ..structs import ElfRela
from .rela import ElfRelocator

# ABI shorthand used in the comments below:
#   A: addend
#   B: base address where the image was loaded
#   P: address of the relocation itself (ElfRela.offset is absolute)
#   S: resolved symbol value
#
# Values confirmed empirically against binutils 2.46 readelf for the sh target.
R_SH_NONE = 0  # No-op.
R_SH_DIR32 = 1  # Write S + A as a 32-bit absolute value.
R_SH_REL32 = 2  # Write S + A - P.
R_SH_GOT32 = 160  # GOT-relative; needs GOT layout we do not model.
R_SH_PLT32 = 161  # PLT-relative; likewise.
R_SH_COPY = 162  # Copy the symbol's contents; needs the source image.
R_SH_GLOB_DAT = 163  # Populate a GOT slot with S.
R_SH_JMP_SLOT = 164  # Populate a PLT/GOT resolver slot with S.
R_SH_RELATIVE = 165  # Write B + A; ignores the symbol value.
R_SH_GOTOFF = 166  # Offset from the GOT base.
R_SH_GOTPC = 167  # PC-relative offset to the GOT base.
R_SH_NUM = 256  # This and higher aren't valid


class SuperHElfRelocator(ElfRelocator):
    """Shared SuperH ELF relocator.

    Deliberately has no ``arch``/``byteorder``, so ``find_subclass`` never
    selects it; the concrete subclasses below do.
    """

    def _pack(self, val: int) -> bytes:
        # `Byteorder`'s values are literally "big"/"little", which is what
        # `int.to_bytes` wants.
        return (val & 0xFFFFFFFF).to_bytes(4, self.byteorder.value)

    def _compute_value(self, rela: ElfRela, elf):
        if rela.type == R_SH_NONE:
            return b""

        if rela.type == R_SH_GLOB_DAT or rela.type == R_SH_JMP_SLOT:
            addend = 0
        elif rela.is_rela:
            addend = rela.addend
        else:
            addend = elf.read_int(rela.offset, 4, self.byteorder)

        if (
            rela.type == R_SH_DIR32
            or rela.type == R_SH_GLOB_DAT
            or rela.type == R_SH_JMP_SLOT
        ):
            # Different semantics, all behave the same
            return self._pack(rela.symbol.value + rela.symbol.baseaddr + addend)
        elif rela.type == R_SH_REL32:
            return self._pack(
                rela.symbol.value + rela.symbol.baseaddr + addend - rela.offset
            )
        elif rela.type == R_SH_RELATIVE:
            return self._pack(elf.address + addend)
        elif rela.type >= 0 and rela.type < R_SH_NUM:
            raise ConfigurationError(
                f"Valid, but unsupported relocation for {rela.symbol.name}: {rela.type}"
            )
        else:
            raise ConfigurationError(
                f"Invalid relocation type for {rela.symbol.name}: {rela.type}"
            )


class SH2AFPUElfRelocator(SuperHElfRelocator):
    arch = platforms.Architecture.SUPERH_SH2A_FPU
    byteorder = platforms.Byteorder.BIG


class SuperH4BEElfRelocator(SuperHElfRelocator):
    arch = platforms.Architecture.SUPERH_SH4
    byteorder = platforms.Byteorder.BIG


class SuperH4ELElfRelocator(SuperHElfRelocator):
    arch = platforms.Architecture.SUPERH_SH4
    byteorder = platforms.Byteorder.LITTLE
