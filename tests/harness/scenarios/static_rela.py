from __future__ import annotations

from .spec import ScenarioInfo, from_variants, script_assert_contains

NATIVE_PARITY = True


def _skip(arch: str) -> str:
    return f"Missing some critical relocation types for {arch}"


_VARIANTS = (
    ("aarch64", _skip("aarch64")),
    ("amd64", None),
    ("armel", _skip("armel")),
    ("armhf", _skip("armhf")),
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
