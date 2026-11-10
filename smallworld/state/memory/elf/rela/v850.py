from ..... import platforms
from .....exceptions import ConfigurationError
from ..structs import ElfRela
from .rela import ElfRelocator

# GCC ELF ABI (EM_V850) relocation types, from binutils' include/elf/v850.h.
# The loader refuses EM_V800 images, whose RH850 ABI numbers its relocations
# differently.
#
# ABI shorthand used in the comments below:
#   A: addend
#   P: address of the relocation itself (ElfRela.offset is absolute)
#   S: resolved symbol value
#
# Instructions store their fields as binutils' bfd/elf32-v850.c inserts them.
R_V850_NONE = 0  # No-op.
R_V850_9_PCREL = 1  # S + A - P into a Bcond's 9-bit displacement.
R_V850_22_PCREL = 2  # S + A - P into a jr or jarl's 22-bit displacement.
R_V850_HI16_S = 3  # High halfword of S + A, adjusted for a signed low half.
R_V850_HI16 = 4  # High halfword of S + A.
R_V850_LO16 = 5  # Low halfword of S + A.
R_V850_ABS32 = 6  # Write S + A as a 32-bit absolute value.
R_V850_LO16_S1 = 37  # Low halfword of S + A, keeping bit 0 (ld.w and st.w).
R_V850_NUM = 52  # This and higher aren't valid


class V850ElfRelocator(ElfRelocator):
    supported_platforms = frozenset(
        {platforms.Platform(platforms.Architecture.V850, platforms.Byteorder.LITTLE)}
    )

    def _pack(self, val: int, size: int) -> bytes:
        return (val & ((1 << (size * 8)) - 1)).to_bytes(size, self.byteorder.value)

    def _pcrel(self, rela: ElfRela, value: int, bits: int) -> int:
        disp = value - rela.offset
        if disp < -(1 << (bits - 1)) or disp >= 1 << (bits - 1):
            raise ConfigurationError(
                f"Relocation {rela.type} for {rela.symbol.name} out of range: {disp:#x}"
            )
        if disp % 2 != 0:
            raise ConfigurationError(
                f"Relocation {rela.type} for {rela.symbol.name} is odd: {disp:#x}"
            )
        return disp

    def _compute_value(self, rela: ElfRela, elf):
        if rela.type == R_V850_NONE:
            return b""

        if not rela.is_rela:
            # GNU as always writes RELA relocations for V850.
            raise ConfigurationError(
                f"REL relocation for {rela.symbol.name} not supported: {rela.type}"
            )

        value = rela.symbol.value + rela.symbol.baseaddr + rela.addend

        if rela.type == R_V850_ABS32:
            return self._pack(value, 4)
        elif rela.type == R_V850_HI16_S:
            return self._pack((value >> 16) + ((value >> 15) & 1), 2)
        elif rela.type == R_V850_HI16:
            return self._pack(value >> 16, 2)
        elif rela.type == R_V850_LO16:
            return self._pack(value, 2)
        elif rela.type == R_V850_LO16_S1:
            if value % 2 != 0:
                raise ConfigurationError(
                    f"Relocation {rela.type} for {rela.symbol.name} is odd: {value:#x}"
                )
            insn = elf.read_int(rela.offset, 2, self.byteorder)
            return self._pack((insn & 1) | (value & 0xFFFE), 2)
        elif rela.type == R_V850_9_PCREL:
            disp = self._pcrel(rela, value, 9)
            insn = elf.read_int(rela.offset, 2, self.byteorder)
            insn &= ~0xF870
            insn |= ((disp & 0x1F0) << 7) | ((disp & 0x0E) << 3)
            return self._pack(insn, 2)
        elif rela.type == R_V850_22_PCREL:
            disp = self._pcrel(rela, value, 22)
            insn = elf.read_int(rela.offset, 4, self.byteorder)
            insn &= ~0xFFFE003F
            insn |= ((disp & 0xFFFE) << 16) | ((disp & 0x3F0000) >> 16)
            return self._pack(insn, 4)
        elif rela.type >= 0 and rela.type < R_V850_NUM:
            raise ConfigurationError(
                f"Valid, but unsupported relocation for {rela.symbol.name}: {rela.type}"
            )
        else:
            raise ConfigurationError(
                f"Invalid relocation type for {rela.symbol.name}: {rela.type}"
            )
