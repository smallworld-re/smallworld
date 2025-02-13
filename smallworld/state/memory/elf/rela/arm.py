from ..... import platforms
from .....exceptions import ConfigurationError
from ..structs import ElfRela
from .rela import ElfRelocator

R_ARM_GLOB_DAT = 21  # Create GOT entry
R_ARM_JUMP_SLOT = 22  # Create PLT entry
R_ARM_RELATIVE = 23  # Adjust by program base
R_ARM_NUM = 256  # This and higher aren't valid


class ArmElfRelocator(ElfRelocator):
    byteorder = platforms.Byteorder.LITTLE

    def _compute_value(self, rela: ElfRela):
        if (
            rela.type == R_ARM_GLOB_DAT
            or rela.type == R_ARM_JUMP_SLOT
            or rela.type == R_ARM_RELATIVE
        ):
            # Different semantics, all behave the same
            val = rela.symbol.value + rela.symbol.baseaddr + rela.addend
            return val.to_bytes(4, "little")
        elif rela.type >= 0 and rela.type < R_ARM_NUM:
            raise ConfigurationError(
                "Valid, but unsupported relocation for {rela.symbol.name}: {rela.type}"
            )
        else:
            raise ConfigurationError(
                "Invalid relocation type for {rela.symbol.name}: {rela.type}"
            )


class Armv5TElfRelocator(ArmElfRelocator):
    arch = platforms.Architecture.ARM_V5T


class Armv6MElfRelocator(ArmElfRelocator):
    arch = platforms.Architecture.ARM_V6M


class Armv7MElfRelocator(ArmElfRelocator):
    arch = platforms.Architecture.ARM_V7M


class Armv7RElfRelocator(ArmElfRelocator):
    arch = platforms.Architecture.ARM_V7R


class Armv7AElfRelocator(ArmElfRelocator):
    arch = platforms.Architecture.ARM_V7A
