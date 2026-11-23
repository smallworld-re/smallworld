import typing

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
    supported_platforms = frozenset(
        {platforms.Platform(platforms.Architecture.POWERPC32, platforms.Byteorder.BIG)}
    )
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


# The VLE code relocations, R_PPC_VLE_REL8 through R_PPC_VLE_ADDR20.
R_PPC_VLE_FIRST = 216
R_PPC_VLE_LAST = 232


class PowerPCVLEElfRelocator(PowerPCElfRelocator):
    """Relocator for PowerPC VLE.

    VLE uses the standard 32-bit data relocations. Its code relocations
    (R_PPC_VLE_*) are not supported, so a relocatable object that has any,
    such as one with an `e_bl` to a global function, cannot be loaded.
    """

    supported_platforms = frozenset(
        {
            platforms.Platform(
                platforms.Architecture.POWERPC32_VLE, platforms.Byteorder.BIG
            )
        }
    )

    def _compute_value(self, rela: ElfRela, elf):
        if R_PPC_VLE_FIRST <= rela.type <= R_PPC_VLE_LAST:
            raise ConfigurationError(
                f"VLE code relocations are not supported: {rela.type} "
                f"for {rela.symbol.name}"
            )
        return super()._compute_value(rela, elf)


# PowerPC64 adds, besides A, B and S above:
#   P: address of the relocation field being updated
#   TOC: the TOC base; see PowerPC64ElfRelocator.prepare_object
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

# st_other bits holding an ELFv2 function's local entry point, as an
# encoded offset from its global entry point; see _local_entry_offset.
STO_PPC64_LOCAL_MASK = 0xE0
STO_PPC64_LOCAL_BIT = 5


def _local_entry_offset(other: int) -> int:
    """The bytes from an ELFv2 function's global entry to its local entry.

    The encoding is binutils' PPC64_LOCAL_ENTRY_OFFSET: 0 and 1 mean the
    entries coincide, and 2 through 6 mean 4, 8, 16, 32 and 64 bytes.
    """
    return ((1 << ((other & STO_PPC64_LOCAL_MASK) >> STO_PPC64_LOCAL_BIT)) >> 2) << 2


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
    supported_platforms = frozenset(
        {platforms.Platform(platforms.Architecture.POWERPC64, platforms.Byteorder.BIG)}
    )
    addrsz = 8

    # The TOC pointer (r2) of an object file, set by prepare_object;
    # None for a linked image, whose TOC the code sets up itself.
    toc_base: typing.Optional[int] = None

    def prepare_object(self, elf, names, offsets, writable) -> None:
        # PowerPC64 code reaches its data through r2, the TOC pointer, and an
        # object file's TOC-relative relocations are computed against it.  A
        # linker puts it 0x8000 past the start of .got, or of .toc when there
        # is no .got, so that a signed 16-bit offset spans 64 KiB of table;
        # the `.TOC.` symbol names the same address.  An object with neither
        # (clang's, or GCC's at -O1, can reach .data with @toc@ha/@toc@l pairs
        # alone) still needs one; GNU ld then uses the start of the first
        # writable section.
        start = None
        for name in (".got", ".toc"):
            start = next((offsets[i] for i in offsets if names[i] == name), None)
            if start is not None:
                break
        if start is None and writable:
            start = min(offsets[i] for i in writable)
        if start is None and offsets:
            start = min(offsets.values())
        if start is not None:
            self.toc_base = elf.address + start + 0x8000

    def linker_symbol_value(self, name: str) -> typing.Optional[int]:
        if name == ".TOC.":
            return self.toc_base
        return None

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
            #
            # Under ELFv2 a direct call enters at the callee's local entry,
            # past the prologue that computes r2 from r12, since the caller
            # neither sets r12 nor changes r2.
            if (elf.processor_flags & EF_PPC64_ABI) == EF_PPC64_ABI_ELFV2:
                symval += _local_entry_offset(rela.symbol.other)
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
            elif self.toc_base is None:
                raise ConfigurationError(
                    f"Relocation {rela.type} for {rela.symbol.name} needs a TOC "
                    "base, which this image does not have"
                )
            else:
                base = self.toc_base
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
