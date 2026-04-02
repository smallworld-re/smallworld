from ..... import platforms
from .....exceptions import ConfigurationError
from ..structs import ElfRela
from .rela import ElfRelocator

# ABI shorthand used in the comments below:
#   A: addend
#   B: base address where the image was loaded
#   G: offset or address of the symbol's GOT slot, depending on relocation
#   GOT: base address of the GOT
#   L: address of the symbol's PLT entry
#   P: address of the relocation field being updated
#   S: resolved symbol value
#   Z: symbol size
R_X86_64_NONE = 0  # No relocation; this entry is a marker only.
R_X86_64_64 = 1  # Write S + A as a 64-bit absolute address/value.
R_X86_64_PC32 = 2  # Write S + A - P as a 32-bit signed PC-relative value.
R_X86_64_GOT32 = 3  # Write the symbol's GOT slot reference as a 32-bit value.
R_X86_64_PLT32 = 4  # Write L + A - P as a 32-bit signed PLT-relative value.
R_X86_64_COPY = 5  # Copy the symbol's runtime data bytes into the relocation target.
R_X86_64_GLOB_DAT = 6  # Populate a GOT slot with S.
R_X86_64_JUMP_SLOT = 7  # Populate a PLT/GOT resolver slot with S.
R_X86_64_RELATIVE = 8  # Write B + A; ignores the symbol value.
R_X86_64_GOTPCREL = 9  # Write G + GOT + A - P for a GOT-indirect reference.
R_X86_64_32 = 10  # Write S + A as a 32-bit zero-extended value.
R_X86_64_32S = 11  # Write S + A as a 32-bit sign-extended value.
R_X86_64_16 = 12  # Write S + A as a 16-bit zero-extended value.
R_X86_64_PC16 = 13  # Write S + A - P as a 16-bit signed PC-relative value.
R_X86_64_8 = 14  # Write S + A as an 8-bit sign-extended value.
R_X86_64_PC8 = 15  # Write S + A - P as an 8-bit signed PC-relative value.
R_X86_64_DTPMOD64 = 16  # Write the TLS module ID containing the symbol.
R_X86_64_DTPOFF64 = 17  # Write the symbol's 64-bit offset within its TLS block.
R_X86_64_TPOFF64 = 18  # Write the symbol's 64-bit offset from the thread pointer.
R_X86_64_TLSGD = 19  # PC-relative reference to the general-dynamic TLS GOT descriptor.
R_X86_64_TLSLD = 20  # PC-relative reference to the local-dynamic TLS GOT descriptor.
R_X86_64_DTPOFF32 = 21  # Write the symbol's 32-bit offset within its TLS block.
R_X86_64_GOTTPOFF = 22  # PC-relative reference to the GOT slot holding the TLS offset.
R_X86_64_TPOFF32 = 23  # Write the symbol's 32-bit offset from the thread pointer.
R_X86_64_PC64 = 24  # Write S + A - P as a 64-bit PC-relative value.
R_X86_64_GOTOFF64 = 25  # Write S + A - GOT as a 64-bit GOT-relative value.
R_X86_64_GOTPC32 = 26  # Write GOT + A - P as a 32-bit signed PC-relative value.
R_X86_64_GOT64 = 27  # Write the symbol's GOT slot reference as a 64-bit value.
R_X86_64_GOTPCREL64 = 28  # Write G + GOT + A - P as a 64-bit PC-relative value.
R_X86_64_GOTPC64 = 29  # Write GOT + A - P as a 64-bit PC-relative value.
R_X86_64_GOTPLT64 = 30  # Write the symbol's GOT/PLT slot reference as a 64-bit value.
R_X86_64_PLTOFF64 = 31  # Write L + A - GOT as a 64-bit GOT-relative PLT value.
R_X86_64_SIZE32 = 32  # Write Z + A as a 32-bit value.
R_X86_64_SIZE64 = 33  # Write Z + A as a 64-bit value.
R_X86_64_GOTPC32_TLSDESC = 34  # PC-relative reference to a TLS descriptor in the GOT.
R_X86_64_TLSDESC_CALL = 35  # Marker for the call instruction in a TLS descriptor sequence.
R_X86_64_TLSDESC = 36  # TLS descriptor relocation; fills the descriptor pair in the GOT.
R_X86_64_IRELATIVE = 37  # Write the return value of an IFUNC resolver located at B + A.
R_X86_64_RELATIVE64 = 38  # Write B + A as a 64-bit relative relocation.
R_X86_64_GOTPCRELX = 41  # Relaxable GOTPCREL form; may rewrite the instruction sequence.
R_X86_64_REX_GOTPCRELX = 42  # Relaxable GOTPCREL form with a known REX-prefix rewrite.
R_X86_64_NUM = 43  # This and higher aren't valid


class AMD64ElfRelocator(ElfRelocator):
    arch = platforms.Architecture.X86_64
    byteorder = platforms.Byteorder.LITTLE

    def _symbol_name(self, rela: ElfRela) -> str:
        return rela.symbol.name if rela.symbol.name else "<anonymous>"

    def _symbol_value(self, rela: ElfRela) -> int:
        return rela.symbol.value + rela.symbol.baseaddr

    def _get_addend(self, rela: ElfRela, elf, size: int) -> int:
        if rela.is_rela:
            return rela.addend
        return int.from_bytes(
            elf.read_bytes(rela.offset, size), self.byteorder.value, signed=True
        )

    def _pack(self, value: int, size: int) -> bytes:
        mask = (1 << (size * 8)) - 1
        return (value & mask).to_bytes(size, self.byteorder.value)

    def _missing_context(self, rela: ElfRela, detail: str) -> None:
        raise ConfigurationError(
            f"Relocation {hex(rela.type)} for {self._symbol_name(rela)} requires "
            f"{detail}, which is not available to AMD64ElfRelocator._compute_value()"
        )

    def _compute_value(self, rela: ElfRela, elf):
        symval = self._symbol_value(rela)

        if rela.type == R_X86_64_NONE:
            return b""
        elif rela.type == R_X86_64_64:
            return self._pack(symval + self._get_addend(rela, elf, 8), 8)
        elif rela.type == R_X86_64_PC32:
            return self._pack(symval + self._get_addend(rela, elf, 4) - rela.offset, 4)
        elif rela.type == R_X86_64_GOT32:
            # This relocation needs the address assigned to the symbol's GOT slot.
            # The current inputs only expose the resolved symbol value, not GOT layout.
            self._missing_context(rela, "the symbol's GOT entry address")
        elif rela.type == R_X86_64_PLT32:
            return self._pack(symval + self._get_addend(rela, elf, 4) - rela.offset, 4)
        elif rela.type == R_X86_64_COPY:
            # Copy relocations need the bytes stored at the resolved symbol,
            # not just the symbol's address and size.
            self._missing_context(rela, "the copied symbol's source bytes")
        elif rela.type == R_X86_64_GLOB_DAT:
            return self._pack(symval, 8)
        elif rela.type == R_X86_64_JUMP_SLOT:
            return self._pack(symval, 8)
        elif rela.type == R_X86_64_RELATIVE:
            return self._pack(elf.address + self._get_addend(rela, elf, 8), 8)
        elif rela.type == R_X86_64_GOTPCREL:
            # This relocation needs both the GOT base and the symbol's GOT slot.
            self._missing_context(rela, "the GOT base and the symbol's GOT entry address")
        elif rela.type == R_X86_64_32:
            return self._pack(symval + self._get_addend(rela, elf, 4), 4)
        elif rela.type == R_X86_64_32S:
            return self._pack(symval + self._get_addend(rela, elf, 4), 4)
        elif rela.type == R_X86_64_16:
            return self._pack(symval + self._get_addend(rela, elf, 2), 2)
        elif rela.type == R_X86_64_PC16:
            return self._pack(symval + self._get_addend(rela, elf, 2) - rela.offset, 2)
        elif rela.type == R_X86_64_8:
            return self._pack(symval + self._get_addend(rela, elf, 1), 1)
        elif rela.type == R_X86_64_PC8:
            return self._pack(symval + self._get_addend(rela, elf, 1) - rela.offset, 1)
        elif rela.type == R_X86_64_DTPMOD64:
            # TLS module relocations need the runtime-assigned TLS module ID.
            self._missing_context(rela, "the TLS module ID for the symbol")
        elif rela.type == R_X86_64_DTPOFF64:
            # Dynamic TLS offsets depend on the module's TLS block layout.
            self._missing_context(rela, "the symbol's offset within its TLS block")
        elif rela.type == R_X86_64_TPOFF64:
            # Initial-exec/local-exec TLS offsets are relative to the thread pointer.
            self._missing_context(rela, "the runtime thread-pointer-relative TLS offset")
        elif rela.type == R_X86_64_TLSGD:
            # General-dynamic TLS uses a two-entry GOT descriptor for the symbol.
            self._missing_context(rela, "the TLS GD descriptor's GOT entry addresses")
        elif rela.type == R_X86_64_TLSLD:
            # Local-dynamic TLS uses a two-entry GOT descriptor for the module.
            self._missing_context(rela, "the TLS LD descriptor's GOT entry addresses")
        elif rela.type == R_X86_64_DTPOFF32:
            # Dynamic TLS offsets depend on the module's TLS block layout.
            self._missing_context(rela, "the symbol's offset within its TLS block")
        elif rela.type == R_X86_64_GOTTPOFF:
            # Initial-exec TLS references a GOT slot holding the thread offset.
            self._missing_context(
                rela, "the GOT entry address holding the symbol's TLS thread offset"
            )
        elif rela.type == R_X86_64_TPOFF32:
            # Initial-exec/local-exec TLS offsets are relative to the thread pointer.
            self._missing_context(rela, "the runtime thread-pointer-relative TLS offset")
        elif rela.type == R_X86_64_PC64:
            return self._pack(symval + self._get_addend(rela, elf, 8) - rela.offset, 8)
        elif rela.type == R_X86_64_GOTOFF64:
            # GOT-relative offsets need the base address of the GOT for this image.
            self._missing_context(rela, "the GOT base address")
        elif rela.type == R_X86_64_GOTPC32:
            # GOT-relative PC computations need the base address of the GOT.
            self._missing_context(rela, "the GOT base address")
        elif rela.type == R_X86_64_GOT64:
            # This relocation needs the address assigned to the symbol's GOT slot.
            self._missing_context(rela, "the symbol's GOT entry address")
        elif rela.type == R_X86_64_GOTPCREL64:
            # This relocation needs both the GOT base and the symbol's GOT slot.
            self._missing_context(rela, "the GOT base and the symbol's GOT entry address")
        elif rela.type == R_X86_64_GOTPC64:
            # GOT-relative PC computations need the base address of the GOT.
            self._missing_context(rela, "the GOT base address")
        elif rela.type == R_X86_64_GOTPLT64:
            # This relocation needs the address assigned to the symbol's GOT/PLT slot.
            self._missing_context(rela, "the symbol's GOT/PLT entry address")
        elif rela.type == R_X86_64_PLTOFF64:
            # GOT-relative PLT offsets need both a PLT target and the GOT base.
            self._missing_context(rela, "the GOT base address")
        elif rela.type == R_X86_64_SIZE32:
            return self._pack(rela.symbol.size + self._get_addend(rela, elf, 4), 4)
        elif rela.type == R_X86_64_SIZE64:
            return self._pack(rela.symbol.size + self._get_addend(rela, elf, 8), 8)
        elif rela.type == R_X86_64_GOTPC32_TLSDESC:
            # TLS descriptors live in the GOT and require a descriptor slot address.
            self._missing_context(rela, "the GOT base and TLS descriptor entry address")
        elif rela.type == R_X86_64_TLSDESC_CALL:
            # This is a marker relocation used to tag a TLS descriptor call sequence.
            return b""
        elif rela.type == R_X86_64_TLSDESC:
            # TLS descriptors require descriptor contents and runtime resolver state.
            self._missing_context(rela, "the TLS descriptor contents and resolver state")
        elif rela.type == R_X86_64_IRELATIVE:
            # Indirect relative relocations require executing an IFUNC resolver
            # at load time and using its return value.
            self._missing_context(rela, "IFUNC resolver execution and its return value")
        elif rela.type == R_X86_64_RELATIVE64:
            return self._pack(elf.address + self._get_addend(rela, elf, 8), 8)
        elif rela.type == 39 or rela.type == 40:
            raise ConfigurationError(
                f"Reserved AMD64 relocation type for {self._symbol_name(rela)}: "
                f"{hex(rela.type)}"
            )
        elif rela.type == R_X86_64_GOTPCRELX:
            # Relaxing this relocation needs either the symbol's GOT slot or
            # instruction-specific rewrite rules. Only the REX variant below has
            # a known, working rewrite in this loader.
            self._missing_context(
                rela,
                "the symbol's GOT entry address or instruction relaxation metadata",
            )
        elif rela.type == R_X86_64_REX_GOTPCRELX:
            addend = self._get_addend(rela, elf, 4)
            elf.write_bytes(rela.offset - 2, b"\x8d")
            return self._pack(symval + addend - rela.offset, 4)
        elif rela.type >= 0 and rela.type < R_X86_64_NUM:
            raise ConfigurationError(
                f"Valid, but unsupported relocation for "
                f"{self._symbol_name(rela)}: {rela.type}"
            )
        else:
            raise ConfigurationError(
                f"Invalid relocation type for "
                f"{self._symbol_name(rela)}: {hex(rela.type)}"
            )
