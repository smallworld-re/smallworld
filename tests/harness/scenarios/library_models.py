from __future__ import annotations

from typing import Any, Mapping

from .common import TestsPath
from .library_data import LIBRARY_MODELS
from .spec import ScenarioInfo, from_variants

NATIVE_PARITY = True

_ARCH_MATRIX = (
    ("aarch64", "AARCH64", "LITTLE"),
    ("amd64", "X86_64", "LITTLE"),
    ("armel", "ARM_V6M", "LITTLE"),
    ("armhf", "ARM_V7A", "LITTLE"),
    ("i386", "X86_32", "LITTLE"),
    ("la64", "LOONGARCH64", "LITTLE"),
    ("m68k", "M68K", "BIG"),
    ("mips", "MIPS32", "BIG"),
    ("mipsel", "MIPS32", "LITTLE"),
    ("mips64", "MIPS64", "BIG"),
    ("mips64el", "MIPS64", "LITTLE"),
    ("ppc", "POWERPC32", "BIG"),
    ("riscv64", "RISCV64", "LITTLE"),
)

_ARCH_BYTEORDER = {arch: (full, byteorder) for arch, full, byteorder in _ARCH_MATRIX}

# Architectures where returning a float/double from a library model is not
# yet supported. Any model whose class is listed in _FLOAT_RETURN_TESTS is
# skipped on these.
_FLOAT_RETURN_SKIPS = {
    "i386": "i386 SysV returns doubles in x87 st0, which is not modeled "
    "(NotImplementedError)",
    "m68k": "m68k float/double return is not modeled (NotImplementedError)",
    "mips": "Unicorn does not expose the f0 FP register for MIPS32",
    "mipsel": "Unicorn does not expose the f0 FP register for MIPS32",
}

# fabs both takes a double argument and returns one, so it needs exactly the
# same skips as the return-only tests: the arches above are the ones without FP
# support, and the n64 MIPS variants (which fabs exercises end to end) stay in.
_FLOAT_RETURN_TESTS = {"C99DifftimeTests", "C99AtofTests", "C99FabsTests"}


def _library_run_factory(info, variant: str, kwargs: Mapping[str, Any]):
    from .. import manifest

    library = kwargs["library"]
    function = kwargs["function"]
    base = kwargs["base"]
    quiet = bool(kwargs.get("quiet", False))
    custom_run = kwargs.get("custom_run", "")
    arch_name, byteorder = _ARCH_BYTEORDER[variant]
    elf = f"{library}/{function}/{function}.{variant}.elf"

    def run(runner):
        args = ["runner.py"]
        if base in {"NoArgLibraryModelTest", "OneArgLibraryModelTest"}:
            if quiet:
                args.append("-q")
            args.extend([elf, arch_name, byteorder])
            stdin = "foobar\n" if base == "OneArgLibraryModelTest" else None
            manifest._run_script(runner, *args, env={"TZ": "UTC"}, stdin=stdin)
            return
        if base == "PrintLibraryModelTest":
            stdout, _ = manifest._run_script(
                runner, "runner.py", elf, arch_name, byteorder
            )
            expected_path = TestsPath / library / function / f"{function}.{variant}.txt"
            expected = expected_path.read_text()
            if "SUCCESS" not in stdout:
                raise AssertionError(f"`SUCCESS` missing from stdout:\n\n{stdout}")
            if stdout != expected:
                raise AssertionError(
                    f"stdout did not match {expected_path}:\n\nexpected:\n{expected}\n\nactual:\n{stdout}"
                )
            return
        if base == "ScanLibraryModelTest":
            manifest._run_script(
                runner, "runner.py", elf, arch_name, byteorder, stdin=""
            )
            return
        if "getenv(foobar);" in custom_run:
            _, stderr = manifest._run_script(
                runner, "runner.py", elf, arch_name, byteorder
            )
            runner.assert_line_contains(stderr, "getenv(foobar);")
            return
        if "system(foobar);" in custom_run:
            _, stderr = manifest._run_script(
                runner, "runner.py", elf, arch_name, byteorder
            )
            runner.assert_line_contains(stderr, "system(foobar);")
            return
        raise AssertionError(
            f"unknown library-model type for {library}/{function}: {base}"
        )

    return run


def _library_description_factory(class_name: str):
    def _factory(variant: str, kwargs: Mapping[str, Any]) -> str:
        return f"{class_name} on {variant}"

    return _factory


def _build_scenario_infos() -> tuple[ScenarioInfo, ...]:
    infos: list[ScenarioInfo] = []
    for item in LIBRARY_MODELS:
        library = item["library"]
        function = item["function"]
        base = item["bases"][0]
        returns_float = item["class_name"] in _FLOAT_RETURN_TESTS
        kwargs = {
            "library": library,
            "function": function,
            "base": base,
            "quiet": bool(item.get("quiet", False)),
            "custom_run": item.get("custom_run_test", ""),
        }
        variants = tuple(
            (arch, _FLOAT_RETURN_SKIPS.get(arch) if returns_float else None)
            for arch, _full, _bo in _ARCH_MATRIX
        )
        infos.append(
            ScenarioInfo(
                prefix=f"{library}:{function}",
                scenario=f"{library}.{function}",
                tags=("library", library, function),
                variants_source=from_variants(
                    variants,
                    kwargs={arch: kwargs for arch, _ in variants},
                ),
                run_factory=_library_run_factory,
                weight=2,
                description_factory=_library_description_factory(item["class_name"]),
            )
        )
    return tuple(infos)


SCENARIO_INFOS = _build_scenario_infos()
