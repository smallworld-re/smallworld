from ..... import platforms
from .....exceptions import ConfigurationError
from ..structs import ElfRela
from .rela import RELOCATED_TLS_MODULE, ElfRelocator

# ABI shorthand used in the comments below:
#   A: addend
#   B: base address where the image was loaded
#   S: resolved symbol value
R_RISCV_64 = 2  # Write S + A as a 64-bit absolute value.
R_RISCV_RELATIVE = 3  # Write B + A; ignores the symbol value.
R_RISCV_COPY = 4  # Copy the symbol's runtime data bytes into the target.
R_RISCV_JUMP_SLOT = 5  # Populate a PLT/GOT resolver slot with S + A.
R_RISCV_TLS_DTPMOD64 = 7  # Write the TLS module ID containing the symbol.
R_RISCV_TLS_DTPREL64 = 9  # Write the symbol's offset within its TLS block, + A.
R_RISCV_TLS_TPREL64 = 11  # Write the symbol's offset from the thread pointer.


class RISCV64ElfRelocator(ElfRelocator):
    arch = platforms.Architecture.RISCV64
    byteorder = platforms.Byteorder.LITTLE

    # The width of an address, and the relocations of that width; RV32
    # overrides them.
    _width = 8
    _absolute = R_RISCV_64
    _dtpmod = R_RISCV_TLS_DTPMOD64
    _dtprel = R_RISCV_TLS_DTPREL64
    _tprel = R_RISCV_TLS_TPREL64

    def _addend(self, rela: ElfRela, elf) -> int:
        if rela.is_rela:
            return rela.addend
        return elf.read_int(rela.offset, self._width, self.byteorder)

    def _pack(self, value: int) -> bytes:
        # Mask to the output width: RELA addends are signed and address
        # sums can wrap, so to_bytes would OverflowError on a raw value.
        return (value & ((1 << (self._width * 8)) - 1)).to_bytes(self._width, "little")

    def _missing_context(self, rela: ElfRela, detail: str) -> None:
        raise ConfigurationError(
            f"Relocation {rela.type} for {rela.symbol.name or '<anonymous>'} requires "
            f"{detail}, which is not available to {type(self).__name__}"
        )

    def _compute_value(self, rela: ElfRela, elf):
        if rela.type == self._absolute or rela.type == R_RISCV_JUMP_SLOT:
            # Different semantics, all behave the same
            return self._pack(
                rela.symbol.value + rela.symbol.baseaddr + self._addend(rela, elf)
            )
        elif rela.type == R_RISCV_RELATIVE:
            return self._pack(elf.address + self._addend(rela, elf))
        elif rela.type == R_RISCV_COPY:
            # Copy relocations need the bytes stored at the resolved symbol,
            # not just the symbol's address.
            self._missing_context(rela, "the copied symbol's source bytes")
        elif rela.type == self._dtpmod:
            # The runtime-assigned TLS module ID; see RELOCATED_TLS_MODULE.
            return self._pack(RELOCATED_TLS_MODULE)
        elif rela.type == self._dtprel:
            # A TLS symbol's value is already its offset within the module's
            # TLS block; adding the load base would make it an address.
            return self._pack(rela.symbol.value + self._addend(rela, elf))
        elif rela.type == self._tprel:
            self._missing_context(
                rela, "the runtime thread-pointer-relative TLS offset"
            )
        raise ConfigurationError(
            f"Unknown relocation type for {rela.symbol.name}: {rela.type}"
        )
