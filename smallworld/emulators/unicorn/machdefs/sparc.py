import unicorn
from unicorn import sparc_const

from ....platforms import Architecture, Byteorder
from ....platforms.defs.sparc import SPARC_WINDOW_REGISTERS
from .machdef import UnicornMachineDef

# %psr after reset, but with the FPU enabled: EF (bit 12) and S (bit 7),
# CWP 0, traps disabled.
_PSR_FPU_ENABLED = 0x1080


class SPARC32MachineDef(UnicornMachineDef):
    """Unicorn machine definition for 32-bit SPARC V8 (LEON3).

    Unicorn rotates its register windows like real hardware, so the %o/%l/%i
    registers always read through the current window.  It has 8 windows and
    never raises a window overflow or underflow trap: a call chain nested 8
    or more `save`s deep silently overwrites the outermost window's
    registers.

    Unicorn 2.1.4 does not support %npc or %y (writes fail with
    UC_ERR_ARG), and reading %psr crashes the process, so the processor
    state register is not exposed at all.  Writing it works, though, and
    `configure_engine` uses that to enable the FPU.
    """

    arch = Architecture.SPARC32
    byteorder = Byteorder.BIG

    uc_arch = unicorn.UC_ARCH_SPARC
    uc_mode = unicorn.UC_MODE_SPARC32 | unicorn.UC_MODE_BIG_ENDIAN
    uc_cpu = sparc_const.UC_CPU_SPARC32_LEON3

    _registers = {
        **{
            name: getattr(sparc_const, f"UC_SPARC_REG_{name.upper()}")
            for name in SPARC_WINDOW_REGISTERS
        },
        "sp": sparc_const.UC_SPARC_REG_SP,
        "fp": sparc_const.UC_SPARC_REG_FP,
        # Writing %pc also sets %npc to %pc + 4.
        "pc": sparc_const.UC_SPARC_REG_PC,
        "npc": 0,
        "y": 0,
    }

    def configure_engine(self, engine: unicorn.Uc) -> None:
        # The CPU resets with the FPU disabled (PSR.EF clear), so the first
        # FP instruction raises an fp_disabled trap.  gcc-built code routinely
        # uses FP registers, even to pass a double to a variadic function,
        # and a real program's startup code would have enabled the FPU.
        engine.reg_write(sparc_const.UC_SPARC_REG_PSR, _PSR_FPU_ENABLED)
