from __future__ import annotations

from .spec import ScenarioInfo, from_variants, script_just_run

NATIVE_PARITY = True

_VARIANTS = tuple(
    (variant, None)
    for arch in ("mips", "mipsel", "mips64", "mips64el")
    for variant in (arch, f"{arch}.angr", f"{arch}.panda", f"{arch}.pcode")
) + (
    # SuperH is the second delay-slot family here.  Unlike MIPS it has no
    # unicorn backend, and its angr machdef is pcode-based rather than VEX, so
    # every sleigh-derived SuperH engine folds the delay slot into its parent
    # branch and single-stepping is permitted on all of them.  panda does not
    # fold: it is real QEMU, so it reports the delay slot's own pc for both the
    # instruction hook and the memory write, exactly as it does for MIPS.
    ("sh2a.pcode", None),
    ("sh2a.angr", None),
    ("sh2a.panda", None),
    ("sh2a.styx", "styx hangs when an instruction or memory hook is installed"),
    ("sh4.pcode", None),
    ("sh4.angr", None),
    ("sh4.panda", None),
    ("sh4el.pcode", None),
    ("sh4el.angr", None),
    ("sh4el.panda", None),
)

SCENARIO_INFO = ScenarioInfo(
    prefix="delay",
    scenario="delay",
    tags=("scenario", "delay"),
    variants_source=from_variants(_VARIANTS),
    run_factory=script_just_run(script_template="delay/delay.{variant}.py"),
)
