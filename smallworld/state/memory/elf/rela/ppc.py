from ..... import platforms
from .....exceptions import ConfigurationError
from ..structs import ElfRela
from .rela import ElfRelocator

R_PPC_GLOB_DAT = 20  # Create GOT entry
R_PPC_JUMP_SLOT = 21  # Create PLT entry
R_PPC_RELATIVE = 22  # Adjust by program base


class PowerPCElfRelocator(ElfRelocator):
    arch = platforms.Architecture.POWERPC32
    byteorder = platforms.Byteorder.BIG
    addrsz = 4

    def _compute_value(self, rela: ElfRela):
        if (
            rela.type == R_PPC_GLOB_DAT
            or rela.type == R_PPC_JUMP_SLOT
            or rela.type == R_PPC_RELATIVE
        ):
            # Different semantics, all behave the same
            val = rela.symbol.value + rela.symbol.baseaddr + rela.addend
            return val.to_bytes(self.addrsz, "big")
        else:
            raise ConfigurationError(
                f"Invalid relocation type for {rela.symbol.name}: {rela.type}"
            )


R_PPC64_ADDR64 = 38  # Adjust by program base, I think...


class PowerPC64ElfRelocator(PowerPCElfRelocator):
    arch = platforms.Architecture.POWERPC64
    byteorder = platforms.Byteorder.BIG
    addrsz = 8

    def _compute_value(self, rela: ElfRela):
        if rela.type == R_PPC64_ADDR64:
            val = rela.symbol.value + rela.symbol.baseaddr + rela.addend
            return val.to_bytes(self.addrsz, "big")
        elif rela.type == R_PPC_JUMP_SLOT:
            # The PowerPC64 JUMP_SLOT relocation is much more complicated.
            # It actually fills in three 64-bit values:
            #
            # 1. The actual function address
            # 2. The TOC base address; serves a similar purpose to the Global Pointer in MIPS.
            # 3. An "environment" pointer, not used by C.
            #
            # We're currently correctly filling in 1.
            # Entry 2. is the address of the GOT section of the containing binary + 0x8000.
            #
            # This requires a reference to the containing binary,
            # which I have no idea how to pass.
            raise NotImplementedError("R_PPC64_JUMP_SLOT not implemented")
        else:
            return super()._compute_value(rela)
