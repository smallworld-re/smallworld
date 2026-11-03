from __future__ import annotations

from typing import Any, Mapping

from .common import TestsPath
from .library_data import LIBRARY_MODELS
from .spec import ScenarioInfo, from_variants

NATIVE_PARITY = True

_ARCH_MATRIX = (
    ("aarch64", "AARCH64", "LITTLE"),
    ("aarch64v85a", "AARCH64_V8_5A", "LITTLE"),
    ("aarch64be", "AARCH64", "BIG"),
    ("aarch64v85abe", "AARCH64_V8_5A", "BIG"),
    ("amd64", "X86_64", "LITTLE"),
    ("armv5t", "ARM_V5T", "LITTLE"),
    ("armv5tbe", "ARM_V5T", "BIG"),
    ("armv4t", "ARM_V4T", "LITTLE"),
    ("armv4tbe", "ARM_V4T", "BIG"),
    ("armv6k", "ARM_V6K", "LITTLE"),
    ("armv6kbe", "ARM_V6K", "BIG"),
    ("armv6m", "ARM_V6M", "LITTLE"),
    ("armv7a", "ARM_V7A", "LITTLE"),
    ("armv7abe", "ARM_V7A", "BIG"),
    ("armv7m", "ARM_V7M", "LITTLE"),
    ("armv7em", "ARM_V7EM", "LITTLE"),
    ("armv7r", "ARM_V7R", "LITTLE"),
    ("armv7rbe", "ARM_V7R", "BIG"),
    ("armv8a", "ARM_V8A", "LITTLE"),
    ("armv8abe", "ARM_V8A", "BIG"),
    ("armv8m", "ARM_V8M", "LITTLE"),
    ("armv8r", "ARM_V8R", "LITTLE"),
    ("armv8rbe", "ARM_V8R", "BIG"),
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

# Skips by function for platforms whose tests build against musl. The M
# profile is Thumb-only, which glibc can't build for. musl differs from the
# glibc ABI the models implement in a few ways, measured case by case.
_MUSL = "M-profile tests build against musl (glibc can't build for Thumb-only CPUs)"
_MUSL_FUNCTION_SKIPS = {
    "ctype_tolower_loc": f"{_MUSL}, which lacks glibc-only __ctype_tolower_loc",
    "ctype_toupper_loc": f"{_MUSL}, which lacks glibc-only __ctype_toupper_loc",
    "__fprintf_chk": f"{_MUSL}, which lacks glibc-only fortified __fprintf_chk",
    "__printf_chk": f"{_MUSL}, which lacks glibc-only fortified __printf_chk",
    "__snprintf_chk": f"{_MUSL}, which lacks glibc-only fortified __snprintf_chk",
    "__sprintf_chk": f"{_MUSL}, which lacks glibc-only fortified __sprintf_chk",
    "gets": f"{_MUSL}, which doesn't declare gets",
    "bsd_signal": f"{_MUSL}, which doesn't declare bsd_signal",
    "pthread_sigmask": f"{_MUSL}; the test reads glibc's sigset_t internals",
    "sigaction": f"{_MUSL}; the test reads glibc's sigset_t internals",
    "sigaddset": f"{_MUSL}; the test reads glibc's sigset_t internals",
    "sigdelset": f"{_MUSL}; the test reads glibc's sigset_t internals",
    "sigemptyset": f"{_MUSL}; the test reads glibc's sigset_t internals",
    "sigfillset": f"{_MUSL}; the test reads glibc's sigset_t internals",
    "sigpending": f"{_MUSL}; the test reads glibc's sigset_t internals",
    "sigprocmask": f"{_MUSL}; the test reads glibc's sigset_t internals",
    "dup": f"{_MUSL}, whose 64-bit off_t lseek the glibc-ABI model doesn't match",
    "open": f"{_MUSL}, whose 64-bit off_t lseek the glibc-ABI model doesn't match",
    "ctype_b_loc": f"{_MUSL}, whose ctype calls isalnum and other unmodeled "
    "classifiers",
}

# Per-architecture skips, by function.
_ARCH_FUNCTION_SKIPS: dict[str, dict[str, str]] = {
    "armv6m": _MUSL_FUNCTION_SKIPS,
    "armv7m": _MUSL_FUNCTION_SKIPS,
    "armv7em": _MUSL_FUNCTION_SKIPS,
    "armv8m": _MUSL_FUNCTION_SKIPS,
}


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
            (
                arch,
                (_FLOAT_RETURN_SKIPS.get(arch) if returns_float else None)
                or _ARCH_FUNCTION_SKIPS.get(arch, {}).get(function),
            )
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
