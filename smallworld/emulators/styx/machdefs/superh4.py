"""Styx machine definitions for SH-4/SH-4A (`Architecture.SUPERH_SH4`).

Reached through Styx's generic ``RawProcessor`` rather than a dedicated
processor crate, so - like ``Target.Ppc4xx`` and ``Target.SuperH2A`` - it is pure
instruction emulation over a flat address space with no peripherals or event
controller. That suits SmallWorld, which maps its own memory.

``Target.SuperH4Be`` / ``Target.SuperH4Le`` do not exist in upstream styx 1.2.0;
they come from ``nix/patches/styx-superh4-target.patch``. Styx's Rust side
already had everything needed (a bundled Ghidra ``SuperH4`` module and
``arch_spec/superh/{sh4eb,sh4el}.rs``), so the patch only adds the Python enum
entries, routes them through ``RawProcessor``, and stops ``build_arch_spec``
hard-wiring SH-4 to the big-endian spec. Both endiannesses are therefore
available here, unlike SH-2A which Ghidra only models big-endian.

**Styx's SH-4 support is immature, and this machdef is correspondingly narrow.**
Unlike ``arch_spec/superh/sh2a.rs``, the SH-4 specs are bare stubs: they set a PC
manager and a generator and nothing else - no floating-point register handlers
and no call-other handlers. What that does and does not mean, measured on a live
processor rather than inferred:

* Integer emulation works, in **both** endiannesses. ``mov``/``nop``/``rts`` with
  its delay slot step correctly and land on the right PC.
* **Single-precision** floating point works (``fadd fr1,fr0`` with 1.5 + 2.25
  gives 3.75). **Double precision works too, but only if the blob loads FPSCR
  with ``lds``.** Setting ``fpscr`` through ``write_register`` and then running
  ``fadd dr2,dr0`` returns garbage - 1.5 + 2.25 gives 480.0, 2.0 + 3.0 gives
  640.0, 1.0 + 1.0 gives 256.0 - because sleigh branches on a separate
  ``FPSCR_PR`` register that only ``lds Rm,FPSCR`` refreshes. That is a
  pcode-wide harness hazard, not an SH-4 or a styx defect; the ``testfloat``
  scenario's SuperH kernel installs FPSCR with ``lds`` and styx passes all five
  double-precision functions on both SH-4 endiannesses (see
  ``docs/concepts/platforms/testfloat_results.csv``). SH-2A is genuinely
  single-precision-only, because ``superh.sinc`` never reads its ``FP_PR``.
* The missing call-other handlers do **not** surface as errors. ``ldtlb``,
  ``mac.l`` and ``ocbi`` all step without raising, so unhandled userops are
  silently not modelled rather than reported. Treat any result that depends on
  them as untrustworthy.
* ``SuperHRegister`` has no ``Sgr``/``Dbr``/``Xd*``/``Xf*`` members at all, and
  the SH-4 arch spec rejects the banked ``r0``-``r7`` and ``ssr``/``spc``, so
  those parts of the platform definition are simply unreachable here.

Prefer ``GhidraEmulator`` or ``PandaEmulator`` for SH-4 work that needs
privileged instructions or any of the userops above.
"""

from styx_emulator.cpu import Backend
from styx_emulator.processor import Target

from ....platforms import Architecture, Byteorder
from ....platforms.defs.superh4 import (
    SH4_PROGRAM_COUNTER_REGISTER,
    SH4_REGISTER_ALIASES,
    SH4_RETURN_ADDRESS_REGISTER,
)
from .machdef import StyxMachineDef
from .superh import superh_register_map

# ``Target.SuperH4Be``/``SuperH4Le`` come from
# ``nix/patches/styx-superh4-target.patch`` and do not exist in an unpatched styx
# wheel - which is what a plain ``pip install smallworld-re[emu-styx]`` gets. Look
# them up defensively rather than at class-definition time so that importing
# SmallWorld still works there. When they are absent the concrete SH-4 machdefs
# below are simply never defined, so nothing registers itself for
# ``Architecture.SUPERH_SH4`` and ``StyxMachineDef.for_platform`` raises its
# usual ``ConfigurationError`` - the honest outcome, and a tidy one, rather than
# an ``AttributeError`` at processor-build time.
#
# ``Target.SuperH2A`` is upstream, so ``superh.py`` uses it unguarded and should
# hard-fail if it ever disappears.
_SUPERH4_BE_TARGET = getattr(Target, "SuperH4Be", None)
_SUPERH4_LE_TARGET = getattr(Target, "SuperH4Le", None)

STYX_SUPPORTS_SUPERH4 = (
    _SUPERH4_BE_TARGET is not None and _SUPERH4_LE_TARGET is not None
)
"""Whether the installed styx wheel exposes the patched SH-4 targets."""


class StyxSuperH4MachineDef(StyxMachineDef):
    """Shared SH-4 definition; the concrete subclasses set ``target``/``byteorder``.

    Has no ``byteorder``/``target``, so ``find_subclass`` never selects it.
    """

    arch = Architecture.SUPERH_SH4
    backend = Backend.Pcode

    address_size = 4
    pc_register = SH4_PROGRAM_COUNTER_REGISTER
    # The architectural name, not the `ra`/`lr` aliases: see the note in
    # `superh.py` - `hook_function` hands this to Styx's own register lookup,
    # and `SuperHRegister` has `Pr` but no `Ra`/`Lr`.
    lr_register = SH4_RETURN_ADDRESS_REGISTER

    # SH-4 has no `tbr`. It *does* architecturally have ssr/spc/sgr/dbr, the
    # banked r0-r7, and the second floating-point bank (xf/xd), but styx's
    # SuperHRegister enum has no Sgr/Dbr/Xd*/Xf* members at all and its SH-4 arch
    # spec rejects the rest, so none of them are mapped. Reading an unmapped name
    # raises a tidy UnsupportedRegisterError; reading one styx knows but the core
    # rejects raises a bare AssertionError from Rust, which is what we are
    # avoiding.
    _registers = superh_register_map(SH4_REGISTER_ALIASES, tbr=False)


if STYX_SUPPORTS_SUPERH4:
    # Defined only when the patched wheel is present; see the note above. These
    # are never referenced by name - `StyxMachineDef.for_platform` discovers them
    # through `__subclasses__()` - so a conditional definition is enough to
    # register or withhold SH-4 support.

    class StyxSuperH4BEMachineDef(StyxSuperH4MachineDef):
        byteorder = Byteorder.BIG
        target = _SUPERH4_BE_TARGET

    class StyxSuperH4ELMachineDef(StyxSuperH4MachineDef):
        byteorder = Byteorder.LITTLE
        target = _SUPERH4_LE_TARGET
