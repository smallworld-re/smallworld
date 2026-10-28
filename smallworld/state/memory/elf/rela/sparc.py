from ..... import platforms
from .....exceptions import ConfigurationError
from ..structs import ElfRela
from .rela import ElfRelocator

R_SPARC_NONE = 0  # No relocation; this entry is a marker only.
R_SPARC_32 = 3
R_SPARC_COPY = 19
R_SPARC_GLOB_DAT = 20
R_SPARC_JMP_SLOT = 21
R_SPARC_RELATIVE = 22
R_SPARC_UA32 = 23
R_SPARC_NUM = 253

# The two instructions the dynamic linker writes into a bound PLT entry.
_SETHI_G1 = 0x03000000  # sethi %hi(value), %g1
_JMP_G1 = 0x81C06000  # jmp %g1 + %lo(value)


class SPARC32ElfRelocator(ElfRelocator):
    arch = platforms.Architecture.SPARC32
    byteorder = platforms.Byteorder.BIG

    def _compute_value(self, rela: ElfRela, elf):
        if not rela.is_rela:
            raise ConfigurationError("Using Rels.  Need to be careful")

        if rela.type == R_SPARC_NONE:
            return b""
        elif rela.type in (R_SPARC_32, R_SPARC_GLOB_DAT, R_SPARC_UA32):
            # S + A, a plain 32-bit word.
            val = rela.symbol.value + rela.symbol.baseaddr + rela.addend
            return (val & 0xFFFFFFFF).to_bytes(4, "big")
        elif rela.type == R_SPARC_RELATIVE:
            # B + A
            val = elf.address + rela.addend
            return (val & 0xFFFFFFFF).to_bytes(4, "big")
        elif rela.type == R_SPARC_JMP_SLOT:
            # 32-bit SPARC binds a PLT entry by rewriting its code rather than
            # storing an address in a GOT slot.  Each 12-byte entry starts as
            #
            #     sethi (. - .PLT0), %g1
            #     ba,a  .PLT0
            #     nop
            #
            # and glibc's sparc_fixup_plt() binds it by replacing the second
            # and third words with a jump to S + A; the first is left alone.
            val = (rela.symbol.value + rela.symbol.baseaddr + rela.addend) & 0xFFFFFFFF
            first = elf.read_bytes(rela.offset, 4)
            return (
                first
                + (_SETHI_G1 | (val >> 10)).to_bytes(4, "big")
                + (_JMP_G1 | (val & 0x3FF)).to_bytes(4, "big")
            )
        elif rela.type == R_SPARC_COPY:
            raise ConfigurationError(
                f"Relocation R_SPARC_COPY for {rela.symbol.name} needs the copied "
                "symbol's source bytes, which are not available to "
                "SPARC32ElfRelocator._compute_value()"
            )
        elif rela.type >= 0 and rela.type < R_SPARC_NUM:
            raise ConfigurationError(
                f"Valid, but unsupported relocation for {rela.symbol.name}: {rela.type}"
            )
        else:
            raise ConfigurationError(
                f"Invalid relocation type for {rela.symbol.name}: {rela.type}"
            )
