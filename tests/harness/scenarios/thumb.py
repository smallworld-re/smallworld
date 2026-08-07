from __future__ import annotations

from typing import Any, Mapping

from .spec import ScenarioInfo, from_variants

NATIVE_PARITY = True

_VARIANT_ARCH_NAMES = {
    "armhf": ("ARM_V7A", "ARM_V7M", "ARM_V7R"),
    "armel": ("ARM_V5T", "ARM_V6M"),
}

_VARIANTS = tuple((variant, None) for variant in _VARIANT_ARCH_NAMES)

_TRACE_PATTERNS = (
    r"single step at 0x1000: <CsInsn 0x1000 \[[0-9a-f]+\]: mov r1, #1>",
    r"single step at 0x1010: <CsInsn 0x1010 \[[0-9a-f]+\]: mov(?:\.w)? r1, #1>",
    r"single step at 0x1020: <CsInsn 0x1020 \[[0-9a-f]+\]: mov r1, #1>",
    r"step block at 0x1000: <CsInsn 0x1000 \[[0-9a-f]+\]: mov r1, #1>",
    r"step block at 0x1010: <CsInsn 0x1010 \[[0-9a-f]+\]: mov(?:\.w)? r1, #1>",
    r"step block at 0x1020: <CsInsn 0x1020 \[[0-9a-f]+\]: mov r1, #1>",
)


def _thumb_run_factory(info, variant: str, kwargs: Mapping[str, Any]):
    from .. import manifest

    arch_names = _VARIANT_ARCH_NAMES[variant]

    def run(runner):
        stdout, stderr = manifest._run_script(runner, f"thumb/thumb.{variant}.py")
        for arch_name in arch_names:
            runner.assert_contains(stdout, f"STEP_{arch_name}=0x6")
            runner.assert_contains(stdout, f"STEP_{arch_name}=0x4")
            for pattern in _TRACE_PATTERNS[:3]:
                runner.assert_contains(stderr, pattern)
            runner.assert_contains(stdout, f"BLOCK_{arch_name}=0x6")
            runner.assert_contains(stdout, f"BLOCK_{arch_name}=0x4")
            for pattern in _TRACE_PATTERNS[3:]:
                runner.assert_contains(stderr, pattern)
            runner.assert_contains(stdout, f"RUN_{arch_name}=0x6")
            runner.assert_contains(stdout, f"RUN_{arch_name}=0x4")
            runner.assert_contains(stdout, f"PERSIST_THUMB_{arch_name}=0x4")
            runner.assert_contains(stdout, f"GET_THUMB_PRE1_{arch_name}=True")
            runner.assert_contains(stdout, f"GET_THUMB_POST1_{arch_name}=False")
            runner.assert_contains(stdout, f"GET_THUMB_PRE2_{arch_name}=False")
            runner.assert_contains(stdout, f"GET_THUMB_POST2_{arch_name}=True")

    return run


SCENARIO_INFO = ScenarioInfo(
    prefix="thumb",
    scenario="thumb",
    tags=("scenario", "thumb"),
    variants_source=from_variants(_VARIANTS),
    run_factory=_thumb_run_factory,
    weight=2,
)
