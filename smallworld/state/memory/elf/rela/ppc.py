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
            # Mask to the output width: RELA addends are signed and address
            # sums can wrap, so to_bytes would OverflowError on a raw value.
            return (val & 0xFFFFFFFF).to_bytes(4, "big")
        elif rela.type == R_PPC_RELATIVE:
            val = elf.address + addend
            return (val & ((1 << (self.addrsz * 8)) - 1)).to_bytes(self.addrsz, "big")
        elif rela.type == R_PPC_GLOB_DAT or rela.type == R_PPC_JUMP_SLOT:
            # Different semantics, all behave the same
            val = rela.symbol.value + rela.symbol.baseaddr + addend
            return (val & ((1 << (self.addrsz * 8)) - 1)).to_bytes(self.addrsz, "big")
        else:
            raise ConfigurationError(
                f"Invalid relocation type for {rela.symbol.name}: {rela.type}"
            )


R_PPC64_ADDR64 = 38  # Write S + A as a 64-bit absolute value.

# e_flags bits holding the ELF ABI version: 1 for ELFv1, 2 for ELFv2,
# or 0 when the file doesn't say (which means ELFv1).
EF_PPC64_ABI = 0x3
EF_PPC64_ABI_ELFV2 = 2


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
            return (val & ((1 << (self.addrsz * 8)) - 1)).to_bytes(self.addrsz, "big")
        elif (
            rela.type == R_PPC_JUMP_SLOT
            and (elf.processor_flags & EF_PPC64_ABI) != EF_PPC64_ABI_ELFV2
        ):
            # Under the ELFv1 ABI (the default when e_flags names none),
            # a PLT slot holds a three-word function descriptor:
            # the entry point, the TOC base, and an environment pointer.
            # The relocation copies the target's descriptor into the slot,
            # which needs the defining image's memory; that isn't modeled.
            #
            # ELFv2 has no function descriptors, so its slot is a plain
            # S + A, which the PowerPC32 code computes at our address width.
            raise NotImplementedError(
                "R_PPC64_JMP_SLOT is only supported for ELFv2 binaries"
            )
        else:
            return super()._compute_value(rela, elf)
