"""Styx machine definition for SH-2A-FPU (`Architecture.SUPERH_SH2A_FPU`).

Styx is the only SmallWorld backend with a *native* SH-2A core rather than a
generic sleigh interpretation: ``Target.SuperH2A`` builds Styx's
``styx-superh2a-processor``, which drives its Pcode backend with
``SuperHVariants::SH2A`` and ``ArchEndian::BigEndian``. Like ``Target.Ppc4xx``
it maps a flat 4 GiB RWX address space, which suits harnesses that place code
and stack at arbitrary low addresses.

Only the Pcode backend works: ``Backend.Unicorn`` raises
``RuntimeError: sh2 processor only supports pcode backend``, because Unicorn has
no SuperH support at all.

As with the PowerPC machdef, the register map below is limited to registers the
core can actually read and write. Styx's ``SuperHRegister`` enum is shared across
the whole SuperH family (111 members, covering SH-3/SH-4 banked registers and
the SH-DSP register file), but the SH-2A arch spec only implements a subset;
reading anything outside it raises a bare ``AssertionError`` from the Rust
backend rather than a tidy ``UnsupportedRegisterError``, which would break
SmallWorld state extraction. Probing a live ``Target.SuperH2A`` shows the
following are rejected and are therefore absent below: ``Ibcr``/``Ibnr``, the
``Fv*`` vectors, ``Ssr``/``Spc``, the SH-2A register-bank shadow copies
(``Bank``, ``R0b``-``R14b``, ``Pcb``-``Ivnb``), the SH-3/SH-4 banked
``R0b0``-``R7b1``, and the SH-DSP registers.

Floating point needs care, and the mapping below is deliberate. Styx's enum
offers both ``Fr0``-``Fr15`` and ``Dr0``-``Dr14``, but they address *independent*
slots in its register file rather than overlapping views, and only the ``Dr*``
slots are the ones its SH-2A core actually executes against. Verified on a live
processor:

* ``fldi1 fr0`` leaves ``Dr0 == 0x3f80000000000000`` and ``Fr0 == 0``;
  ``fldi1 fr1`` leaves ``Dr0 == 0x000000003f800000``. So ``Dr{n}`` is the real
  register pair, with ``fr{n}`` its upper half and ``fr{n+1}`` its lower - which
  is exactly how ``platforms.defs.superh.SH2AFPU`` models it (``fr{n}`` at
  numeric offset 4 of ``dr{n}``, ``fr{n + 1}`` at offset 0).
* Writing ``Dr0`` through the API and then executing ``fmov fr0,fr2`` correctly
  propagates the value, so API-written FP state *is* observed by execution.
* Writing ``Fr1`` and then executing ``fmov fr1,fr0`` does **not** observe it.
  ``SuperHRegister.Fr*`` is a dead slot on this core.

So only ``dr0``-``dr14`` are mapped. SmallWorld loses nothing by this:
``state.RegisterAlias.apply``/``extract`` are no-ops, so machine state is only
ever pushed to and pulled from the *parent* registers, and the single-precision
halves are computed in Python. The one visible consequence is that a direct
``emulator.read_register("fr0")`` against this backend raises
``UnsupportedRegisterError``; read ``dr0`` instead, or go through the CPU state
model.

With that mapping, **single-precision** arithmetic is correct - ``fadd fr1,fr0``
on 1.5 + 2.25 gives 3.75, and a value written to ``dr0`` is observed by a
subsequent ``fmov``. **Double-precision is broken**: with ``FPSCR.PR`` set,
``fadd dr2,dr0`` returns garbage (1.5 + 2.25 gives 480.0, 2.0 + 3.0 gives 640.0,
1.0 + 1.0 gives 256.0). That is a styx-wide SuperH limitation - SH-4 behaves
identically - so treat styx as single-precision-only for SuperH.
"""

from styx_emulator.arch.superh import SuperHRegister
from styx_emulator.cpu import Backend
from styx_emulator.processor import Target

from ....platforms import Architecture, Byteorder
from ....platforms.defs.superh import (
    SH2A_PROGRAM_COUNTER_REGISTER,
    SH2A_REGISTER_ALIASES,
    SH2A_RETURN_ADDRESS_REGISTER,
    SH2A_STATUS_REGISTER,
)
from .machdef import StyxMachineDef


def superh_register_map(aliases: dict, *, tbr: bool = False) -> dict:
    """Build a SmallWorld-name -> ``SuperHRegister`` map.

    Shared with the SH-4 machdef: both families reach the same core register file
    through Styx (r0-r15, the control registers, and the ``Dr*`` floating-point
    pairs), differing only in whether ``tbr`` exists.
    """
    registers = {
        # *** General-Purpose Registers ***
        **{f"r{i}": getattr(SuperHRegister, f"R{i}") for i in range(16)},
        # *** Control Registers ***
        SH2A_PROGRAM_COUNTER_REGISTER: SuperHRegister.Pc,
        SH2A_STATUS_REGISTER: SuperHRegister.Sr,
        SH2A_RETURN_ADDRESS_REGISTER: SuperHRegister.Pr,
        "gbr": SuperHRegister.Gbr,
        "vbr": SuperHRegister.Vbr,
        # *** Multiply-Accumulate Registers ***
        "mach": SuperHRegister.Mach,
        "macl": SuperHRegister.Macl,
        # *** Floating-Point Registers ***
        # Only the double-precision pairs; see the module docstring for why
        # ``SuperHRegister.Fr*`` is unusable.
        **{f"dr{i}": getattr(SuperHRegister, f"Dr{i}") for i in range(0, 16, 2)},
        # *** Floating-Point Control Registers ***
        "fpscr": SuperHRegister.Fpscr,
        "fpul": SuperHRegister.Fpul,
    }
    if tbr:
        # Table base register; SH-2A only, backs `jsr/n @@(disp,tbr)`.
        registers["tbr"] = SuperHRegister.Tbr
    # SmallWorld's aliases (sp/fp/ra/lr) are just names to Styx, so they map
    # straight onto whichever architectural register they shadow.
    for alias, parent in aliases.items():
        registers[alias] = registers[parent]
    return registers


class StyxSH2AFPUMachineDef(StyxMachineDef):
    arch = Architecture.SUPERH_SH2A_FPU
    byteorder = Byteorder.BIG

    target = Target.SuperH2A
    backend = Backend.Pcode

    address_size = 4
    pc_register = SH2A_PROGRAM_COUNTER_REGISTER
    # SuperH returns through PR. This must be the *architectural* name, not the
    # `ra`/`lr` aliases SmallWorld also exposes: `StyxEmulator.hook_function`
    # passes `lr_register` straight to Styx's `ProcessorCore.read_register`,
    # which resolves it against `SuperHRegister` - and that enum has `Pr` but no
    # `Ra`/`Lr`. (ARM and PowerPC get away with `"lr"` because `ArmRegister.Lr`
    # and `Ppc32Register.Lr` do exist.) With an alias here the read raises, the
    # emulator swallows it, and the hooked function silently falls through into
    # its own body instead of returning.
    lr_register = SH2A_RETURN_ADDRESS_REGISTER

    _registers = superh_register_map(SH2A_REGISTER_ALIASES, tbr=True)
