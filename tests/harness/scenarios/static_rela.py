from __future__ import annotations

from .spec import ScenarioInfo, from_variants, script_assert_contains

NATIVE_PARITY = True


def _skip(arch: str) -> str:
    return f"Missing some critical relocation types for {arch}"


# A BE8 object file holds its code big-endian, as BE32 does; the linker
# swaps it to little-endian when it links with --be8. SmallWorld loads the
# object as-is, so it would execute big-endian code on a BE8 CPU.
_BE8_OBJECTS = "BE8 object files hold big-endian code that only the linker converts"

_VARIANTS = (
    ("aarch64", None),
    ("aarch64v85a", None),
    ("aarch64be", None),
    ("aarch64v85abe", None),
    ("amd64", None),
    ("armv6k", None),
    ("armv6kbe", _BE8_OBJECTS),
    ("armv5t", None),
    ("armv5tbe", None),
    ("armv4t", None),
    ("armv4tbe", None),
    ("armv7m", None),
    ("armv7em", None),
    ("armv6m", None),
    ("armv8m", None),
    ("armv7a", None),
    ("armv7abe", _BE8_OBJECTS),
    ("armv7r", None),
    ("armv7rbe", _BE8_OBJECTS),
    ("armv8a", None),
    ("armv8abe", _BE8_OBJECTS),
    ("armv8r", None),
    ("armv8rbe", _BE8_OBJECTS),
    ("i386", _skip("i386")),
    ("la64", _skip("la64")),
    ("m68k", _skip("m68k")),
    ("mips", _skip("mips")),
    ("mipsel", _skip("mipsel")),
    ("mips64", _skip("mips64")),
    ("mips64el", _skip("mips64el")),
    ("ppc", _skip("ppc")),
    ("riscv64", _skip("riscv64")),
)

SCENARIO_INFO = ScenarioInfo(
    prefix="static_rela",
    scenario="static_rela",
    tags=("scenario", "static_rela"),
    variants_source=from_variants(_VARIANTS),
    run_factory=script_assert_contains(
        "foobar",
        script_template="static_rela/static_rela.{variant}.py",
        args=("foobar",),
    ),
)
