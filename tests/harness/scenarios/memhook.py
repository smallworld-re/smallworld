from __future__ import annotations

from typing import Any, Mapping

from .spec import ScenarioInfo, from_variants, script_assert_outputs

NATIVE_PARITY = True

_VARIANTS = (
    ("aarch64", None),
    ("aarch64.angr", None),
    ("aarch64.panda", None),
    ("aarch64.pcode", None),
    ("amd64", None),
    ("amd64.angr", None),
    ("amd64.panda", None),
    ("amd64.pcode", None),
    ("armel", None),
    ("armel.angr", None),
    ("armel.panda", None),
    ("armel.pcode", None),
    ("armhf", None),
    ("armhf.angr", None),
    ("armhf.panda", None),
    ("armhf.pcode", None),
    ("i386", None),
    ("i386.angr", None),
    ("i386.panda", "Waiting for panda-ng"),
    ("i386.pcode", None),
    ("la64.angr", None),
    ("la64.pcode", None),
    ("m68k", None),
    ("m68k.pcode", None),
    ("mips", None),
    ("mips.angr", None),
    ("mips.panda", None),
    ("mips.pcode", None),
    ("mipsel", None),
    ("mipsel.angr", None),
    ("mipsel.panda", None),
    ("mipsel.pcode", None),
    ("mips64", None),
    ("mips64.angr", None),
    ("mips64.panda", "Panda failure"),
    ("mips64.pcode", None),
    ("mips64el.angr", None),
    ("mips64el.panda", "Panda failure"),
    ("mips64el.pcode", None),
    ("ppc", None),
    ("ppc.angr", None),
    ("ppc.panda", None),
    ("ppc.pcode", None),
    ("riscv64", None),
    ("riscv64.angr", None),
    ("riscv64.pcode", None),
)

# Per the legacy harness, these arches print results with 8-byte fields.
_WIDE_ARCHES = {"aarch64", "amd64", "i386", "la64", "mips64", "mips64el", "riscv64"}


def _memhook_expectations(
    variant: str, kwargs: Mapping[str, Any]
) -> tuple[tuple[tuple[str, ...], str], ...]:
    arch = variant.split(".")[0]
    width = "8" if arch in _WIDE_ARCHES else "4"
    qux_addr = "0x1030" if width == "8" else "0x1034"
    lines = (
        "foo: read 1 bytes at 0x1004",
        f"bar: read {width} bytes at 0x1010",
        f"baz: read {width} bytes at 0x1020",
        f"qux: read {width} bytes at {qux_addr}",
    )
    return tuple(((), line) for line in lines)


def _memhook_variant_transform(variant: str) -> str:
    # The Ghidra-backed memhook scripts use the legacy '.ghidra' suffix on disk
    # rather than '.pcode' — except m68k.pcode, which uses .pcode literally.
    if variant.endswith(".pcode") and variant != "m68k.pcode":
        return variant[: -len(".pcode")] + ".ghidra"
    return variant


SCENARIO_INFO = ScenarioInfo(
    prefix="memhook",
    scenario="memhook",
    tags=("scenario", "memhook"),
    variants_source=from_variants(_VARIANTS),
    run_factory=script_assert_outputs(
        _memhook_expectations,
        script_template="memhook/memhook.{variant}.py",
        line=True,
        variant_transform=_memhook_variant_transform,
    ),
)
