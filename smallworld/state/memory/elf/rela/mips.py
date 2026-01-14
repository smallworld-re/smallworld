from ..... import platforms
from .....exceptions import ConfigurationError
from ..structs import ElfRela
from .rela import ElfRelocator

R_MIPS_NONE = 0
R_MIPS_32 = 2  # 32-bit direct
R_MIPS_REL32 = 3
R_MIPS_64 = 18  # 64-bit direct
R_MIPS_JUMP_SLOT = 127


class MIPSElfRelocator(ElfRelocator):
    arch = platforms.Architecture.MIPS32
    byteorder = platforms.Byteorder.BIG

    def _compute_value(self, rela: ElfRela, elf):
        # Unpack a MIPS64 relocation.
        #
        # It's not possible to build a 64-bit address in one instruction in MIPS64.
        # Rather than tell the linker to live with it,
        # MIPS64 relocation entries can define up to three nested relocations,
        # with relocations 2 and 3 acting as if the symbol value were the result
        # of the previous relocation.
        #
        # There's a fourth argument, which is a parameter to relocation 2, I think.
        # Don't want to waste those bytes...
        rela_types = []
        # rela_special = (rela.type >> 24) & 0xFF
        for i in range(0, 3):
            rela_types.append((rela.type >> (i * 8)) & 0xFF)

        if rela.is_rela:
            addend = rela.addend
        else:
            addend = elf.read_int(
                rela.offset,
                4 if self.arch is platforms.Architecture.MIPS32 else 8,
                self.byteorder,
            )

        val = rela.symbol.value + rela.symbol.baseaddr
        is_64 = False
        for i in range(0, 3):
            rela_type = rela_types[i]
            if rela_type == R_MIPS_NONE:
                break
            elif rela_type == R_MIPS_32 or rela_type == R_MIPS_REL32:
                # 32-bit direct
                val = val + addend
            elif rela_type == R_MIPS_64:
                # 64-bit direct
                val = val + addend
                is_64 = True
            elif rela_type == R_MIPS_JUMP_SLOT:
                # Jump slot.
                # Do NOT add the addend.
                # For rels, it will be pre-populated with the offset of the PLT resolver,
                # not an actual addend.
                is_64 = self.arch is platforms.Architecture.MIPS64
            else:
                raise ConfigurationError(
                    f"Invalid relocation type {i} for {rela.symbol.name}: {rela_type}"
                )

        return val.to_bytes(
            8 if is_64 else 4,
            "big" if self.byteorder == platforms.Byteorder.BIG else "little",
        )


class MIPSELElfRelocator(MIPSElfRelocator):
    byteorder = platforms.Byteorder.LITTLE


class MIPS64ElfRelocator(MIPSElfRelocator):
    arch = platforms.Architecture.MIPS64


class MIPS64ELElfRelocator(MIPSElfRelocator):
    arch = platforms.Architecture.MIPS64
    byteorder = platforms.Byteorder.LITTLE
