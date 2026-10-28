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


# PowerPC64 adds, besides A, B and S above:
#   P: address of the relocation field being updated
#   TOC: the TOC base, ElfExecutable.toc_base
# and these halves of a 16-bit field's value x:
#   lo(x) = x & 0xFFFF
#   hi(x) = (x >> 16) & 0xFFFF
#   ha(x) = ((x + 0x8000) >> 16) & 0xFFFF, the high half adjusted for the
#           sign of lo(x), so that `addis` then `addi` reassembles x.
# The *_DS forms fill a DS-form field, whose low two bits are opcode bits.
R_PPC64_REL24 = 10  # Write (S + A - P) >> 2 into a branch's 24-bit LI field.
R_PPC64_REL32 = 26  # Write S + A - P as a 32-bit value.
R_PPC64_ADDR64 = 38  # Write S + A as a 64-bit absolute value.
R_PPC64_REL64 = 44  # Write S + A - P as a 64-bit value.
R_PPC64_TOC16 = 47  # Write S + A - TOC as a signed 16-bit value.
R_PPC64_TOC16_LO = 48  # Write lo(S + A - TOC).
R_PPC64_TOC16_HI = 49  # Write hi(S + A - TOC).
R_PPC64_TOC16_HA = 50  # Write ha(S + A - TOC).
R_PPC64_TOC16_DS = 63  # Write S + A - TOC into a DS field.
R_PPC64_TOC16_LO_DS = 64  # Write lo(S + A - TOC) into a DS field.
R_PPC64_REL16 = 249  # Write S + A - P as a signed 16-bit value.
R_PPC64_REL16_LO = 250  # Write lo(S + A - P).
R_PPC64_REL16_HI = 251  # Write hi(S + A - P).
R_PPC64_REL16_HA = 252  # Write ha(S + A - P).

# e_flags bits holding the ELF ABI version: 1 for ELFv1, 2 for ELFv2,
# or 0 when the file doesn't say (which means ELFv1).
EF_PPC64_ABI = 0x3
EF_PPC64_ABI_ELFV2 = 2


# Relocations that fill a 16-bit field, by what they are relative to
# and which part of the value they take ("all" checks it fits).
_PPC64_HALF_RELOCATIONS = {
    R_PPC64_TOC16: ("TOC", "all"),
    R_PPC64_TOC16_LO: ("TOC", "lo"),
    R_PPC64_TOC16_HI: ("TOC", "hi"),
    R_PPC64_TOC16_HA: ("TOC", "ha"),
    R_PPC64_TOC16_DS: ("TOC", "all"),
    R_PPC64_TOC16_LO_DS: ("TOC", "lo"),
    R_PPC64_REL16: ("P", "all"),
    R_PPC64_REL16_LO: ("P", "lo"),
    R_PPC64_REL16_HI: ("P", "hi"),
    R_PPC64_REL16_HA: ("P", "ha"),
}


class PowerPC64ElfRelocator(PowerPCElfRelocator):
    arch = platforms.Architecture.POWERPC64
    byteorder = platforms.Byteorder.BIG
    addrsz = 8

    def _compute_value(self, rela: ElfRela, elf):
        if rela.is_rela:
            addend = rela.addend
        else:
            addend = elf.read_int(rela.offset, self.addrsz, self.byteorder)

        symval = rela.symbol.value + rela.symbol.baseaddr
        if rela.type == R_PPC64_ADDR64:
            val = symval + addend
            return (val & ((1 << (self.addrsz * 8)) - 1)).to_bytes(self.addrsz, "big")
        elif rela.type == R_PPC64_REL64:
            val = symval + addend - rela.offset
            return (val & ((1 << 64) - 1)).to_bytes(8, "big")
        elif rela.type == R_PPC64_REL32:
            val = symval + addend - rela.offset
            return (val & 0xFFFFFFFF).to_bytes(4, "big")
        elif rela.type == R_PPC64_REL24:
            # A relocatable object's calls to other functions are `bl`s that
            # a linker would route through a stub when the target is out of
            # range; there is no stub here, so the target must be in range.
            val = symval + addend - rela.offset
            if val & 0x3 or not -(1 << 25) <= val < (1 << 25):
                raise ConfigurationError(
                    f"{rela.symbol.name} at {hex(symval)} is out of `bl` range "
                    f"of {hex(rela.offset)}"
                )
            insn = elf.read_int(rela.offset, 4, self.byteorder)
            insn = (insn & ~0x03FFFFFC) | (val & 0x03FFFFFC)
            return insn.to_bytes(4, "big")
        elif rela.type in _PPC64_HALF_RELOCATIONS:
            relative_to, half = _PPC64_HALF_RELOCATIONS[rela.type]
            if relative_to == "P":
                base = rela.offset
            elif elf.toc_base is None:
                raise ConfigurationError(
                    f"Relocation {rela.type} for {rela.symbol.name} needs a TOC "
                    "base, which this image does not have"
                )
            else:
                base = elf.toc_base
            val = symval + addend - base
            if half == "lo":
                field = val & 0xFFFF
            elif half == "hi":
                field = (val >> 16) & 0xFFFF
            elif half == "ha":
                field = ((val + 0x8000) >> 16) & 0xFFFF
            else:
                if not -0x8000 <= val < 0x8000:
                    raise ConfigurationError(
                        f"Relocation {rela.type} for {rela.symbol.name} "
                        f"overflows 16 bits: {hex(val)}"
                    )
                field = val & 0xFFFF
            if rela.type in (R_PPC64_TOC16_DS, R_PPC64_TOC16_LO_DS):
                old = elf.read_int(rela.offset, 2, self.byteorder)
                field = (field & 0xFFFC) | (old & 0x3)
            return field.to_bytes(2, "big")
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
