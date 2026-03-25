from ..... import platforms
from .....exceptions import ConfigurationError
from ..structs import ElfRela
from .rela import ElfRelocator

R_X86_64_64 = 1  # Direct 64-bit
R_X86_64_PC32 = 2  # PC-relative 32-bit signed
R_X86_64_PLT32 = 4  # 32-bit PLT address
R_X86_64_GLOB_DAT = 6  # Create GOT entry
R_X86_64_JUMP_SLOT = 7  # Create PLT entry
R_X86_64_RELATIVE = 8  # Adjust by program base
R_X86_64_REX_GOTPCRELX = 42  # Relaxable PC or PC/GOT relative 32-bit
R_X86_64_NUM = 43  # This and higher aren't valid


class AMD64ElfRelocator(ElfRelocator):
    arch = platforms.Architecture.X86_64
    byteorder = platforms.Byteorder.LITTLE

    def _compute_value(self, rela: ElfRela, elf):
        if (
            rela.type == R_X86_64_GLOB_DAT
            or rela.type == R_X86_64_JUMP_SLOT
            or rela.type == R_X86_64_RELATIVE
            or rela.type == R_X86_64_64
        ):
            # Different semantics, all behave the same
            if rela.is_rela:
                addend = rela.addend
            else:
                addend = elf.read_int(rela.offset, 8, self.byteorder)

            val = rela.symbol.value + rela.symbol.baseaddr + addend
            return val.to_bytes(8, "little")
        elif (
            rela.type == R_X86_64_PC32
            or rela.type == R_X86_64_PLT32
            or rela.type == R_X86_64_REX_GOTPCRELX
        ):
            if rela.is_rela:
                addend = rela.addend
            else:
                addend = elf.read_int(rela.offset, 4, self.byteorder)

            if rela.type == R_X86_64_REX_GOTPCRELX:
                elf.write_bytes(rela.offset - 2, b"\x8d")

            val = rela.symbol.value + rela.symbol.baseaddr + addend - rela.offset
            if val < 0:
                val += 1 << 32
            return val.to_bytes(4, "little")
        elif rela.type >= 0 and rela.type < R_X86_64_NUM:
            raise ConfigurationError(
                f"Valid, but unsupported relocation for {rela.symbol.name}: {rela.type}"
            )
        else:
            raise ConfigurationError(
                f"Invalid relocation type for {rela.symbol.name}: {hex(rela.type)}"
            )
