from __future__ import annotations

from .spec import ScenarioInfo, from_variants, script_assert_contains, script_just_run

NATIVE_PARITY = True

_NIX_SYSROOT = "Pending Nix sysroot for {}"
_ZIG_QEMU_MIPS = "Pending fix for zig/QEMU MIPS ABI conflict"
_ZIG_QEMU_MIPS_LOAD = "Pending fix to zig/QEMU MIPS ABI problem"
_MIPS64_LD_LOAD = "Pending solution to crashes in mips64 ld.so"
_MIPS64_LD_ACTUATE = "Pending fix for crashes in mips64 ld.so"
_PPC64_LD_LOAD = "Pending solution to crashes in ppc64 ld.so"
_PPC64_LD_ACTUATE = "Pending fix for crashes in ppc64 ld.so"
_PANDA_NG = "Waiting for panda-ng"

_LOAD_VARIANTS = (
    ("aarch64", None),
    ("amd64", None),
    ("armel", _NIX_SYSROOT.format("armel")),
    ("armhf", _NIX_SYSROOT.format("armhf")),
    ("i386", _NIX_SYSROOT.format("i386")),
    ("mips", _ZIG_QEMU_MIPS_LOAD),
    ("mipsel", _ZIG_QEMU_MIPS_LOAD),
    ("mips64", _MIPS64_LD_LOAD),
    ("mips64el", _MIPS64_LD_LOAD),
    ("ppc", None),
    ("ppc64", _PPC64_LD_LOAD),
)

_ACTUATE_VARIANTS = (
    ("aarch64", None),
    ("aarch64.angr", None),
    ("aarch64.panda", _PANDA_NG),
    ("aarch64.pcode", None),
    ("amd64", None),
    ("amd64.angr", "Problem loading rflags"),
    ("amd64.panda", _PANDA_NG),
    ("amd64.pcode", None),
    ("armel", _NIX_SYSROOT.format("armel")),
    ("armel.angr", _NIX_SYSROOT.format("armel")),
    ("armel.panda", _NIX_SYSROOT.format("armel")),
    ("armel.pcode", _NIX_SYSROOT.format("armel")),
    ("armhf", _NIX_SYSROOT.format("armhf")),
    ("armhf.angr", _NIX_SYSROOT.format("armhf")),
    ("armhf.panda", _NIX_SYSROOT.format("armhf")),
    ("armhf.pcode", _NIX_SYSROOT.format("armhf")),
    ("i386", "Problem loading segment registers"),
    ("i386.angr", "Problem loading eflags"),
    ("i386.panda", _NIX_SYSROOT.format("i386")),
    ("i386.pcode", _NIX_SYSROOT.format("i386")),
    ("mips", _ZIG_QEMU_MIPS),
    ("mips.angr", _ZIG_QEMU_MIPS),
    ("mips.panda", _ZIG_QEMU_MIPS),
    ("mips.pcode", _ZIG_QEMU_MIPS),
    ("mipsel", _ZIG_QEMU_MIPS),
    ("mipsel.angr", _ZIG_QEMU_MIPS),
    ("mipsel.panda", _ZIG_QEMU_MIPS),
    ("mipsel.pcode", _ZIG_QEMU_MIPS),
    ("mips64.angr", _MIPS64_LD_ACTUATE),
    ("mips64.panda", _MIPS64_LD_ACTUATE),
    ("mips64.pcode", _MIPS64_LD_ACTUATE),
    ("mips64el.angr", _MIPS64_LD_ACTUATE),
    ("mips64el.panda", _MIPS64_LD_ACTUATE),
    ("mips64el.pcode", _MIPS64_LD_ACTUATE),
    ("ppc", None),
    ("ppc.angr", None),
    ("ppc.panda", _PANDA_NG),
    ("ppc.pcode", None),
    ("ppc64", _PPC64_LD_ACTUATE),
    ("ppc64.angr", _PPC64_LD_ACTUATE),
    ("ppc64.pcode", _PPC64_LD_ACTUATE),
)

SCENARIO_INFOS = (
    ScenarioInfo(
        prefix="elf_core.load",
        scenario="elf_core.load",
        tags=("scenario", "elf_core", "load"),
        variants_source=from_variants(_LOAD_VARIANTS),
        run_factory=script_just_run(
            script_template="elf_core/load/elf_core.{variant}.py",
        ),
        weight=2,
    ),
    ScenarioInfo(
        prefix="elf_core.actuate",
        scenario="elf_core.actuate",
        tags=("scenario", "elf_core"),
        variants_source=from_variants(_ACTUATE_VARIANTS),
        run_factory=script_assert_contains(
            "foobar",
            script_template="elf_core/actuate/elf_core.{variant}.py",
        ),
        weight=2,
    ),
)
