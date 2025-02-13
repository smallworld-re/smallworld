from ..... import platforms
from .....exceptions import ConfigurationError
from ..structs import ElfRela
from .rela import ElfRelocator

R_MIPS_32 = 2  # 32-bit direct
R_MIPS_64 = 18  # 64-bit direct


class MIPSElfRelocator(ElfRelocator):
    arch = platforms.Architecture.MIPS32
    byteorder = platforms.Byteorder.BIG

    def _compute_value(self, rela: ElfRela):
        # Because mypy doesn't believe I know what I'm doing...

        if rela.type == R_MIPS_32:
            # 32-bit direct
            val = rela.symbol.value + rela.symbol.baseaddr + rela.addend
            return val.to_bytes(
                4, "big" if self.byteorder == platforms.Byteorder.BIG else "little"
            )
        elif rela.type == R_MIPS_64:
            # 64-bit direct
            val = rela.symbol.value + rela.symbol.baseaddr + rela.addend
            return val.to_bytes(
                8, "big" if self.byteorder == platforms.Byteorder.BIG else "little"
            )
        else:
            raise ConfigurationError(
                "Invalid relocation type for {rela.symbol.name}: {rela.type}"
            )


class MIPSELElfRelocator(MIPSElfRelocator):
    byteorder = platforms.Byteorder.LITTLE


class MIPS64ElfRelocator(MIPSElfRelocator):
    arch = platforms.Architecture.MIPS64


class MIPS64ELElfRelocator(MIPSElfRelocator):
    arch = platforms.Architecture.MIPS64
    byteorder = platforms.Byteorder.LITTLE
