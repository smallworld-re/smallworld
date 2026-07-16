"""Styx machine definition for 32-bit PowerPC (`Architecture.POWERPC32`).

Styx exposes two PowerPC firmware cores through its Python bindings, selected
via the optional ``cpu_model`` argument to :class:`StyxEmulator`:

* ``"ppc405"`` (default) — an IBM/AMCC PowerPC 405 on Styx's Pcode backend
  (``Target.Ppc4xx``). It maps a flat 4 GiB RWX address space, which suits
  harnesses that place code and stack at arbitrary low addresses.
* ``"mpc860"`` — a Freescale PowerQUICC I MPC860 on Styx's Unicorn backend
  (``Target.Mpc8xx``); the MPC8xx Pcode backend is unimplemented and panics.

Both are big-endian PPC32 and share the ``Ppc32Register`` set. The register map
below is intentionally limited to the registers *both* cores can read and write:
the PPC405 Pcode register file does not expose the FPRs or the cr1-cr6 condition
fields, and reading an unsupported register raises a backend error (not a tidy
``UnsupportedRegisterError``), which would break SmallWorld state extraction.
GPRs, pc, lr, ctr, msr, xer and cr0/cr7 are available on both cores.

Styx has no 64-bit PowerPC core, so ``Architecture.POWERPC64`` deliberately has
no machine definition and resolves to a ``ConfigurationError``.
"""

from styx_emulator.arch.ppc32 import Ppc32Register
from styx_emulator.cpu import Backend
from styx_emulator.processor import Target

from ....platforms import Architecture, Byteorder
from .machdef import StyxMachineDef


class StyxPowerPC32MachineDef(StyxMachineDef):
    arch = Architecture.POWERPC32
    byteorder = Byteorder.BIG
    # Default core is the PowerPC 405 on the Pcode backend.
    target = Target.Ppc4xx
    backend = Backend.Pcode

    address_size = 4
    pc_register = "pc"
    lr_register = "lr"

    # cpu_model (lowercased) -> (Styx Target, Styx Backend). Lets one
    # POWERPC32/BIG machdef reach both PowerPC cores Styx exposes; MPC860 only
    # runs under the Unicorn backend (its Pcode path is unimplemented).
    cpu_models = {
        "ppc405": (Target.Ppc4xx, Backend.Pcode),
        "ppc4xx": (Target.Ppc4xx, Backend.Pcode),
        "mpc860": (Target.Mpc8xx, Backend.Unicorn),
        "mpc8xx": (Target.Mpc8xx, Backend.Unicorn),
    }

    _registers = {
        "pc": Ppc32Register.Pc,
        "lr": Ppc32Register.Lr,
        "ctr": Ppc32Register.Ctr,
        "msr": Ppc32Register.Msr,
        "xer": Ppc32Register.Xer,
        "spr_xer": Ppc32Register.Xer,
        # PPC405's Pcode register file only exposes cr0 and cr7 (not cr1-cr6).
        "cr0": Ppc32Register.Cr0,
        "cr7": Ppc32Register.Cr7,
        # r1 is the stack pointer, r31 the frame/base pointer.
        "sp": Ppc32Register.R1,
        "bp": Ppc32Register.R31,
    }
    # General-purpose registers r0-r31.
    for _i in range(32):
        _registers[f"r{_i}"] = getattr(Ppc32Register, f"R{_i}")
    del _i
