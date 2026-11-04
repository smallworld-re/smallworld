from __future__ import annotations

from typing import Any, Mapping

from .spec import ScenarioInfo, from_variants, script_assert_outputs

NATIVE_PARITY = True

_VARIANTS = (
    ("aarch64", None),
    ("aarch64v85a", None),
    ("aarch64be", None),
    ("aarch64v85abe", None),
    ("aarch64.angr", None),
    ("aarch64v85a.angr", None),
    ("aarch64be.angr", None),
    ("aarch64v85abe.angr", None),
    ("aarch64.panda", None),
    ("aarch64v85a.panda", None),
    ("aarch64be.panda", None),
    ("aarch64v85abe.panda", None),
    ("aarch64.pcode", None),
    ("aarch64v85a.pcode", None),
    ("aarch64be.pcode", None),
    ("aarch64v85abe.pcode", None),
    ("aarch64.triton", None),
    ("aarch64v85a.triton", None),
    ("amd64", None),
    ("amd64.angr", None),
    ("amd64.panda", None),
    ("amd64.pcode", None),
    ("amd64.triton", None),
    ("armv6k", None),
    ("armv6kbe", None),
    ("armv5t", None),
    ("armv5tbe", None),
    ("armv4t", None),
    ("armv4tbe", None),
    ("armv7m", None),
    ("armv7em", None),
    ("armv6m", None),
    ("armv8m", None),
    ("armv6k.angr", None),
    ("armv6kbe.angr", None),
    ("armv5t.angr", None),
    ("armv5tbe.angr", None),
    ("armv4t.angr", None),
    ("armv4tbe.angr", None),
    ("armv7m.angr", None),
    ("armv7em.angr", None),
    ("armv6m.angr", None),
    ("armv8m.angr", None),
    ("armv6k.panda", None),
    ("armv6kbe.panda", None),
    ("armv5t.panda", None),
    ("armv5tbe.panda", None),
    ("armv4t.panda", None),
    ("armv4tbe.panda", None),
    ("armv7m.panda", None),
    ("armv7em.panda", None),
    ("armv6m.panda", None),
    ("armv8m.panda", None),
    ("armv6k.pcode", None),
    ("armv6kbe.pcode", None),
    ("armv5t.pcode", None),
    ("armv5tbe.pcode", None),
    ("armv4t.pcode", None),
    ("armv4tbe.pcode", None),
    ("armv7m.pcode", None),
    ("armv7em.pcode", None),
    ("armv6m.pcode", None),
    ("armv8m.pcode", None),
    ("armv6k.triton", None),
    ("armv5t.triton", None),
    ("armv4t.triton", None),
    ("armv7m.triton", None),
    ("armv7em.triton", None),
    ("armv6m.triton", None),
    ("armv8m.triton", None),
    ("armv7a", None),
    ("armv7abe", None),
    ("armv7r", None),
    ("armv7rbe", None),
    ("armv8a", None),
    ("armv8abe", None),
    ("armv8r", None),
    ("armv8rbe", None),
    ("armv7a.angr", None),
    ("armv7abe.angr", None),
    ("armv7r.angr", None),
    ("armv7rbe.angr", None),
    ("armv8a.angr", None),
    ("armv8abe.angr", None),
    ("armv8r.angr", None),
    ("armv8rbe.angr", None),
    ("armv7a.panda", None),
    ("armv7abe.panda", None),
    ("armv7r.panda", None),
    ("armv7rbe.panda", None),
    ("armv8a.panda", None),
    ("armv8abe.panda", None),
    ("armv8r.panda", None),
    ("armv8rbe.panda", None),
    ("armv7a.pcode", None),
    ("armv7abe.pcode", None),
    ("armv7r.pcode", None),
    ("armv7rbe.pcode", None),
    ("armv8a.pcode", None),
    ("armv8abe.pcode", None),
    ("armv8r.pcode", None),
    ("armv8rbe.pcode", None),
    ("armv7a.triton", None),
    ("armv7r.triton", None),
    ("armv8a.triton", None),
    ("armv8r.triton", None),
    ("i386", None),
    ("i386.angr", None),
    ("i386.panda", "Waiting for panda-ng"),
    ("i386.pcode", None),
    ("i386.triton", None),
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
    ("riscv64.triton", None),
)

# Per the legacy harness, these arches print results with 8-byte fields.
_WIDE_ARCHES = {
    "aarch64",
    "aarch64v85a",
    "aarch64be",
    "aarch64v85abe",
    "amd64",
    "i386",
    "la64",
    "mips64",
    "mips64el",
    "riscv64",
}


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
        # A single access at 0x1040 straddles the two adjacent span hooks; both
        # must fire (SW-143). Both sit in the first 4-byte chunk, so the access
        # is reported at 0x1040 on 32-bit (4B) and 64-bit (8B) alike.
        f"span_lo: read {width} bytes at 0x1040",
        f"span_hi: read {width} bytes at 0x1040",
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
