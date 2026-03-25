from ..... import platforms
from .....exceptions import ConfigurationError
from ..structs import ElfRela
from .rela import ElfRelocator

R_AARCH64_ABS64 = 257  # Direct 64-bit
R_AARCH64_PREL32 = 261  # PC-relative 32-bit
R_AARCH64_ADR_PREL_PG_HI21 = 275  # PC-rel ADRP immediate
R_AARCH64_ADR_ABS_LO12_NC = 277  # Absolute ADD immediate
R_AARCH64_CALL26 = 283  # 26-bit call offset
R_AARCH64_ADR_GOT_PAGE = 311  # I don't know.
R_AARCH64_LD64_GOT_LO12_NC = 312  # I also don't know
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
        elif rela.type == R_AARCH64_CALL26:
            orig = elf.read_int(rela.offset, 4, self.byteorder)

            val = rela.symbol.value + rela.symbol.baseaddr + rela.addend - rela.offset
            if val < 0:
                val += 1 << 32
            val &= 0xFFFFFFF
            val >>= 2
            val |= orig
            return val.to_bytes(4, "little")

        elif rela.type == R_AARCH64_PREL32:
            val = rela.symbol.value + rela.symbol.baseaddr + rela.addend - rela.offset
            if val < 0:
                val += 1 << 32
            return val.to_bytes(4, "little")
        elif rela.type == R_AARCH64_ADR_PREL_PG_HI21:
            orig = elf.read_int(rela.offset, 4, self.byteorder)
            val = rela.symbol.value + rela.symbol.baseaddr + rela.addend - rela.offset

            raise ConfigurationError("TODO: Please handle R_AARCH64_ADR_PREL_PG_HI21")

            return val.to_bytes(4, "little")
        elif rela.type == R_AARCH64_ADR_ABS_LO12_NC:
            orig = elf.read_int(rela.offset, 4, self.byteorder)
            val = rela.symbol.value + rela.symbol.baseaddr + rela.addend
            val &= 0xFFF
            val |= orig
            return val.to_bytes(4, "little")
        elif rela.type == R_AARCH64_ADR_GOT_PAGE:
            # This references a GOT section before its creation.
            # We probably don't have one of those.
            raise ConfigurationError("Unhandled relocation R_AARCH64_ADR_GOT_PAGE")
        elif rela.type == R_AARCH64_LD64_GOT_LO12_NC:
            # This references a GOT section from a static binary.
            # We may not have one of those.
            raise ConfigurationError("Unhandled relocation R_AARCH64_LD64_GOT_LO12_NC")
        else:
            raise ConfigurationError(
                f"Unknown relocation type for {rela.symbol.name}: {hex(rela.type)}"
            )
