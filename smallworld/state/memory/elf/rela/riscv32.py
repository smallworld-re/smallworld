from ..... import platforms
from .riscv64 import RISCV64ElfRelocator

R_RISCV_32 = 1  # Write S + A as a 32-bit absolute value.
R_RISCV_TLS_DTPMOD32 = 6  # Write the TLS module ID containing the symbol.
R_RISCV_TLS_DTPREL32 = 8  # Write the symbol's offset within its TLS block, + A.
R_RISCV_TLS_TPREL32 = 10  # Write the symbol's offset from the thread pointer.


class RISCV32ElfRelocator(RISCV64ElfRelocator):
    """RV64's relocations, at 32 bits."""

    arch = platforms.Architecture.RISCV32

    _width = 4
    _absolute = R_RISCV_32
    _dtpmod = R_RISCV_TLS_DTPMOD32
    _dtprel = R_RISCV_TLS_DTPREL32
    _tprel = R_RISCV_TLS_TPREL32
