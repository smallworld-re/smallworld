from ..... import platforms
from .....exceptions import ConfigurationError
from ..structs import ElfRela
from .rela import ElfRelocator

# ABI shorthand used in the comments below:
#   A: addend
#   B: base address where the image was loaded
#   S: resolved symbol value
R_PPC_ABS32 = 1  # Write S + A as a 32-bit absolute value.
R_PPC_GLOB_DAT = 20  # Populate a GOT slot with S + A.
R_PPC_JUMP_SLOT = 21  # Populate a PLT/GOT resolver slot with S + A.
R_PPC_RELATIVE = 22  # Write B + A; ignores the symbol value.


class PowerPCElfRelocator(ElfRelocator):
    arch = platforms.Architecture.POWERPC32
    byteorder = platforms.Byteorder.BIG
    addrsz = 4

    def _compute_value(self, rela: ElfRela, elf):
        if rela.is_rela:
            addend = rela.addend
        else:
            addend = elf.read_int(rela.offset, self.addrsz, self.byteorder)

        if rela.type == R_PPC_ABS32:
            val = rela.symbol.value + rela.symbol.baseaddr + addend
            return val.to_bytes(4, "big")
        elif rela.type == R_PPC_RELATIVE:
            val = elf.address + addend
            return val.to_bytes(self.addrsz, "big")
        elif rela.type == R_PPC_GLOB_DAT or rela.type == R_PPC_JUMP_SLOT:
            # Different semantics, all behave the same
            val = rela.symbol.value + rela.symbol.baseaddr + addend
            return val.to_bytes(self.addrsz, "big")
        else:
            raise ConfigurationError(
                f"Invalid relocation type for {rela.symbol.name}: {rela.type}"
            )


R_PPC64_ADDR64 = 38  # Write S + A as a 64-bit absolute value.


class PowerPC64ElfRelocator(PowerPCElfRelocator):
    arch = platforms.Architecture.POWERPC64
    byteorder = platforms.Byteorder.BIG
    addrsz = 8

    def _compute_value(self, rela: ElfRela, elf):
        if rela.is_rela:
            addend = rela.addend
        else:
            addend = elf.read_int(rela.offset, self.addrsz, self.byteorder)

        if rela.type == R_PPC64_ADDR64:
            val = rela.symbol.value + rela.symbol.baseaddr + addend
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
            # Entry 2. is the address of the GOT/TOC section of the containing binary + 0x8000.
            #
            # This requires a reference to the containing binary,
            # which I have no idea how to pass.
            raise NotImplementedError("R_PPC64_JUMP_SLOT not implemented")
        else:
            return super()._compute_value(rela, elf)
