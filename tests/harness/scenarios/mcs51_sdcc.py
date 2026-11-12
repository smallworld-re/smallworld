"""SDCC-compiled C on the 8051, and SDCC's calling conventions.

The programs in ``tests/mcs51_sdcc`` are C, built twice by
``tests/mcs51_cc.sh``: once with SDCC's default calling convention
(``ABI.SDCC``), and once with ``--stack-auto`` (``ABI.SDCCSTACKAUTO``).  Each
image is loaded with ``Executable.from_ihex``, with the linker's map for
symbols, and runs from the reset vector, through SDCC's startup code and main,
to the loop main returns to.

``mcs51_sdcc.abi.<abi>``: ``abi.mcs51.c`` calls functions the scenario
replaces with models built on the ABI's model class.  The models check the
arguments they read - every C type, pointers into internal RAM, XDATA and
code, a variadic call - and return values the program stores, which the
scenario checks.

``mcs51_sdcc.libc.<abi>``: ``libc.mcs51.c`` runs SDCC's own C library.

``mcs51_sdcc.libc_models.<abi>``: the same program, with every library
function it calls replaced by SmallWorld's C99 models for the ABI.  Its
results must match the library's.

Both libc programs are built a third time, ``cip51``, for a Silicon Labs
CIP-51 device, the C8051F330: in the medium memory model, with SDCC's default
convention and pdata moved to XDATA 0x7E00.  That device pages MOVX @Ri
through EMI0CN, not P2, so the scenario names EMI0CN in the CPU's
``xpage_sfr`` - as the linker map records it, which must agree with
``mcs51_xpage_sfr`` - and leaves P2 at its reset value, 0xFF: paged through
P2, pdata would land in the wrong page.  They are built a fourth time,
``c8051f020``, the same way for the C8051F020, whose EMI0CN is at another
address, 0xAF; that build adds an ``MCS51Device`` for the C8051F020 to the
machine instead, which sets ``xpage_sfr``, and, with no table of the
device's interrupts, leaves the emulator taking the 8052's.  And a fifth
time, ``c8051f040``, for the C8051F040, whose EMI0CN is at 0xA2, and which
pages its SFRs; its ``MCS51Device`` pages them, and the scenario maps SFR
pages 0-0x0F.  And a sixth time, ``efm8bb2``, for the EFM8BB2, whose EMI0CN is
at 0xE7; SDCC has no header for it, so ``efm8bb2.h`` declares its SFRs.

``mcs51_sdcc.flash.cip51``: ``flash.cip51.c``, built only for the
C8051F330, erases and writes its own flash, unlocking it with FLKEY, and
writes it while locked.  The scenario maps the flash page it writes, and
checks what it read back, and that XDATA was left alone.
``mcs51_sdcc.flash_efm8bb2.efm8bb2``: ``flash_efm8bb2.c`` erases a 512-byte
page of the EFM8BB2's code flash and one of its 64-byte pages, and writes in
the second; the scenario checks what it read back.

``mcs51_sdcc.sfrpages.<device>``: ``sfrpages.c``, built for the C8051F040,
C8051F060 and C8051F120, reaches SFRs on several pages, and takes an
interrupt with the SFR page stack enabled and disabled.  The scenario
checks what it read.  ``mcs51_sdcc.sfrpages_f36x.c8051f360``:
``sfrpages_f36x.c`` does the like for the C8051F360, which pages its SFRs
differently.

``mcs51_sdcc.interrupts.cip51``: ``interrupts.cip51.c``, built only for the
C8051F330, requests the device's interrupts beyond the 8052's.  The scenario
adds an ``MCS51Device`` for the C8051F330, so the emulators take them, and
checks the order the handlers ran in.
"""

from __future__ import annotations

import contextlib
import io
import logging
import struct
import sys
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from .common import TestsPath, make_emulator, split_variant
from .spec import ScenarioInfo, from_variants, just_run

NATIVE_PARITY = True

_DIR = TestsPath / "mcs51_sdcc"
_VARIANTS = ("mcs51.angr", "mcs51.pcode")
_ABIS = ("sdcc", "sdccstackauto")
_PROGRAMS = ("abi", "libc", "libc_models")
# (program, build): each program under each ABI, and the libc programs for
# the C8051F330 as well.
_CASES = tuple((program, abi) for program in _PROGRAMS for abi in _ABIS) + (
    ("libc", "cip51"),
    ("libc_models", "cip51"),
    ("libc", "c8051f020"),
    ("libc_models", "c8051f020"),
    ("libc", "c8051f040"),
    ("libc_models", "c8051f040"),
    ("libc", "efm8bb2"),
    ("libc_models", "efm8bb2"),
    ("interrupts", "cip51"),
    ("flash", "cip51"),
    ("flash_efm8bb2", "efm8bb2"),
    ("sfrpages", "c8051f040"),
    ("sfrpages", "c8051f060"),
    ("sfrpages", "c8051f120"),
    ("sfrpages_f36x", "c8051f360"),
)

# The device each CIP-51 build is for, and whether the scenario emulates it
# with an MCS51Device rather than setting xpage_sfr from the linker map.
_DEVICES = {
    "cip51": ("C8051F330", False),
    "c8051f020": ("C8051F020", True),
    "c8051f040": ("C8051F040", True),
    "c8051f060": ("C8051F060", True),
    "c8051f120": ("C8051F120", True),
    "c8051f360": ("C8051F360", True),
    "efm8bb2": ("EFM8BB21F16G", True),
}

# P2, and its reset value.
_SFR_P2 = 0xA0
_P2_RESET = 0xFF

SCENARIO_INFOS = tuple(
    ScenarioInfo(
        prefix=f"mcs51_sdcc.{program}.{build}",
        scenario=f"mcs51_sdcc.{program}.{build}",
        tags=("scenario", "mcs51_sdcc"),
        variants_source=from_variants(tuple((v, None) for v in _VARIANTS)),
        run_factory=just_run(),
    )
    for program, build in _CASES
)

# The library functions libc.mcs51.c calls: map symbol, model name.  SDCC's
# string.h makes memcpy a macro for __memcpy.
_LIBC_FUNCTIONS = {
    "_strcpy": "strcpy",
    "_strcat": "strcat",
    "_strlen": "strlen",
    "_strcmp": "strcmp",
    "_strchr": "strchr",
    "_memset": "memset",
    "___memcpy": "memcpy",
    "_toupper": "toupper",
    "_atoi": "atoi",
    "_abs": "abs",
    "_sprintf": "sprintf",
    "_malloc": "malloc",
    "_free": "free",
    "_qsort": "qsort",
    "_bsearch": "bsearch",
    "_puts": "puts",
    "_printf": "printf",
}


class _Capture(io.StringIO):
    # SmallWorld's stdout decodes what models write with the stream's
    # encoding, which a plain StringIO lacks.
    encoding = "utf-8"


def can_run(scenario: str, variant: str) -> bool:
    parts = scenario.split(".")
    return (
        len(parts) == 3
        and parts[0] == "mcs51_sdcc"
        and (parts[1], parts[2]) in _CASES
        and variant in _VARIANTS
    )


def _program_exit(code) -> int:
    # SDCC's startup code ends `lcall _main`, then loops forever.
    return code.get_symbol_value("__sdcc_program_startup") + 3


def _parameter_addresses(code, function: str) -> List[int]:
    # Where SDCC's default convention puts the function's arguments after the
    # first; none under --stack-auto.
    names = set(code.get_symbol_names())
    addresses = []
    n = 2
    while f"{function}_PARM_{n}" in names:
        addresses.append(code.get_symbol_value(f"{function}_PARM_{n}"))
        n += 1
    return addresses


def _setup(
    smallworld, image, device: Optional[str] = None, emulate_device: bool = False
):
    from smallworld.platforms.defs.mcs51 import (
        MCS51_IDATA_BASE,
        MCS51_SFR_BASE,
        MCS51_XDATA_BASE,
        mcs51_xpage_sfr,
    )

    platform = smallworld.platforms.Platform(
        smallworld.platforms.Architecture.MCS51, smallworld.platforms.Byteorder.BIG
    )
    machine = smallworld.state.Machine()
    cpu = smallworld.state.cpus.CPU.for_platform(platform)
    machine.add(cpu)

    with open(f"{image}.ihx") as file, open(f"{image}.map") as map_file:
        code = smallworld.state.memory.code.Executable.from_ihex(
            file, map_file=map_file, platform=platform
        )
    machine.add(code)

    # Reset state; SDCC's startup code sets SP and initializes memory.
    cpu.pc.set(0)
    cpu.sp.set(0x07)
    for register in ("acc", "b", "psw", "dptr"):
        getattr(cpu, register).set(0)
    for i in range(8):
        getattr(cpu, f"r{i}").set(0)

    # A build for a CIP-51 device takes xpage_sfr from the linker map, or,
    # with emulate_device, from an MCS51Device, which sets the device's
    # interrupts and SFR paging too; either way, it must agree with the
    # device lookup.  A device that pages its SFRs has pages 0-0x0F mapped,
    # all zero: the programs that take interrupts enable the page stack
    # themselves, so that they test the SFR the device's table names.
    sfrs = bytearray(0x100)
    if device is not None:
        xpage_sfr = code.get_map_value("__XPAGE")
        if xpage_sfr != mcs51_xpage_sfr(device):
            raise ValueError(f"the map's __XPAGE is {xpage_sfr!r}")
        if emulate_device:
            mcs51_device = smallworld.state.cpus.MCS51Device(device)
            machine.add(mcs51_device)
            paging = mcs51_device.sfr_paging
            if paging is not None:
                sfrs = bytearray(0x1000)
        else:
            cpu.xpage_sfr.set(xpage_sfr)
        sfrs[_SFR_P2] = _P2_RESET
    for base, content in (
        (MCS51_IDATA_BASE, bytes(0x100)),
        (MCS51_SFR_BASE, bytes(sfrs)),
        (MCS51_XDATA_BASE, bytes(0x8000)),
    ):
        machine.add(smallworld.state.memory.RawMemory.from_bytes(content, base))
    return platform, machine, code


def _report(checks: Dict[str, Tuple[Any, Any]], errors: Sequence[str]) -> int:
    failed = bool(errors)
    for error in errors:
        print(f"FAIL {error}")
    for name, (actual, expected) in checks.items():
        status = "ok" if actual == expected else "FAIL"
        failed = failed or actual != expected
        print(f"{status:4} {name}: {actual!r} (expected {expected!r})")
    if failed:
        sys.exit(1)
    return 0


def _run_abi(smallworld, abi_name: str, engine: str) -> int:
    from smallworld.state.models.cstd import ArgumentType as T
    from smallworld.state.models.mcs51.sdcc import MCS51SDCCModel
    from smallworld.state.models.mcs51.sdccstackauto import MCS51SDCCStackAutoModel

    base: Any = MCS51SDCCModel if abi_name == "sdcc" else MCS51SDCCStackAutoModel
    platform, machine, code = _setup(smallworld, _DIR / f"abi.{abi_name}.mcs51")
    errors: List[str] = []

    def expect(what: str, actual, wanted) -> None:
        if actual != wanted:
            errors.append(f"{what}: {actual!r}, expected {wanted!r}")

    class CheckArgs(base):
        name = "check_args"
        argument_types = [
            T.CHAR,
            T.INT,
            T.LONG,
            T.POINTER,
            T.POINTER,
            T.POINTER,
            T.FLOAT,
        ]
        return_type = T.LONG

        def model(self, emulator) -> None:
            wanted = [
                ord("A"),
                -1234,
                0x12345678,
                code.get_symbol_value("_xbuf"),
                code.get_symbol_value("_ibuf"),
                code.get_symbol_value("_cbuf"),
                1.5,
            ]
            for i, kind in enumerate(self.argument_types):
                expect(
                    f"check_args arg {i + 1}",
                    self.get_argument(i, kind, emulator),
                    wanted[i],
                )
            for i, data in ((3, b"xd"), (4, b"id"), (5, b"code")):
                pointer = self.get_argument(i, T.POINTER, emulator)
                expect(
                    f"check_args *arg {i + 1}",
                    emulator.read_memory(pointer, len(data)),
                    data,
                )
            self.set_return_value(emulator, -0x7EADBEEF)

    class Twice(base):
        name = "twice"
        argument_types = [T.LONGLONG]
        return_type = T.LONGLONG

        def model(self, emulator) -> None:
            x = self.get_arg1(emulator)
            expect("twice arg 1", x, 0x0102030405060708)
            self.set_return_value(emulator, x * 2)

    class Pick(base):
        name = "pick"
        argument_types = [T.CHAR]
        return_type = T.POINTER

        def model(self, emulator) -> None:
            which = self.get_arg1(emulator)
            buffers = ("_ibuf", "_xbuf", "_cbuf")
            self.set_return_value(emulator, code.get_symbol_value(buffers[which]))

    class Half(base):
        name = "half"
        argument_types = [T.FLOAT]
        return_type = T.FLOAT

        def model(self, emulator) -> None:
            x = self.get_arg1(emulator)
            expect("half arg 1", x, 3.0)
            self.set_return_value(emulator, x / 2)

    class Sum(base):
        name = "sum"
        argument_types = [T.INT]
        return_type = T.INT
        variadic = True

        def model(self, emulator) -> None:
            n = self.get_arg1(emulator)
            expect("sum arg 1", n, 3)
            varargs = self.get_varargs()
            values = [varargs.get_next_argument(T.INT, emulator) for _ in range(n)]
            expect("sum varargs", values, [100, -20, 3])
            self.set_return_value(emulator, sum(values))

    for cls in (CheckArgs, Twice, Pick, Half, Sum):
        model = cls(code.get_symbol_value(f"_{cls.name}"))
        model.parameter_addresses = _parameter_addresses(code, f"_{cls.name}")
        machine.add(model)

    emulator = make_emulator(smallworld, platform, engine)
    emulator.add_exit_point(_program_exit(code))
    machine.emulate(emulator)

    def xdata(name: str, size: int) -> bytes:
        return emulator.read_memory(code.get_symbol_value(name), size)

    checks = {
        "r_check_args": (
            int.from_bytes(xdata("_r_check_args", 4), "little", signed=True),
            -0x7EADBEEF,
        ),
        "r_twice": (
            int.from_bytes(xdata("_r_twice", 8), "little"),
            0x020406080A0C0E10,
        ),
        "r_pick": (xdata("_r_pick", 3), b"ixc"),
        "r_half": (struct.unpack("<f", xdata("_r_half", 4))[0], 1.5),
        "r_sum": (int.from_bytes(xdata("_r_sum", 2), "little", signed=True), 83),
    }
    return _report(checks, errors)


def _count_calls(model, name: str, called: Set[str]) -> None:
    # Records in called each time the model runs.
    run = model.model

    def model_and_count(emulator) -> None:
        called.add(name)
        run(emulator)

    model.model = model_and_count


def _run_libc(smallworld, build: str, engine: str, models: bool) -> int:
    from smallworld.platforms.defs.mcs51 import MCS51_XDATA_BASE

    device, emulate_device = _DEVICES.get(build, (None, False))
    platform, machine, code = _setup(
        smallworld, _DIR / f"libc.{build}.mcs51", device, emulate_device
    )
    # SDCC links its library into the image, so a model that never ran would
    # leave SDCC's own code to pass the checks.
    called: Set[str] = set()
    abi = (
        smallworld.platforms.ABI.SDCCSTACKAUTO
        if build == "sdccstackauto"
        else smallworld.platforms.ABI.SDCC
    )

    if models:
        heap = smallworld.state.memory.heap.BumpAllocator(
            MCS51_XDATA_BASE + 0x8000, 0x100
        )
        machine.add(heap)
        for symbol, name in _LIBC_FUNCTIONS.items():
            model = smallworld.state.models.Model.lookup(
                name, platform, abi, code.get_symbol_value(symbol)
            )
            model.parameter_addresses = _parameter_addresses(code, symbol)
            if hasattr(model, "heap"):
                model.heap = heap
            _count_calls(model, name, called)
            machine.add(model)

    emulator = make_emulator(smallworld, platform, engine)
    emulator.add_exit_point(_program_exit(code))
    stdout = _Capture()
    with contextlib.redirect_stdout(stdout):
        machine.emulate(emulator)

    def xdata(name: str, size: int) -> bytes:
        return emulator.read_memory(code.get_symbol_value(name), size)

    def string(name: str) -> bytes:
        return xdata(name, 32 if name != "_buf2" else 16).split(b"\0")[0]

    def integer(name: str) -> int:
        return int.from_bytes(xdata(name, 2), "little", signed=True)

    if models:
        output = stdout.getvalue()
    else:
        output = xdata("_out", xdata("_outlen", 1)[0]).decode()
    sys.stdout.write(stdout.getvalue())

    checks = {
        "buf": (string("_buf"), b"hello, 8051"),
        "buf2": (string("_buf2"), b"zzzhello"),
        "fmt": (string("_fmt"), b"-7-ab-beef"),
        "r_strlen": (integer("_r_strlen"), 11),
        "r_strcmp > 0": (integer("_r_strcmp") > 0, True),
        "r_strchr": (integer("_r_strchr"), 5),
        "r_upper": (integer("_r_upper"), ord("Q")),
        "r_atoi": (integer("_r_atoi"), -321),
        "r_abs": (integer("_r_abs"), 42),
        "r_sprintf": (integer("_r_sprintf"), 10),
        "r_malloc": (integer("_r_malloc"), 4),
        "sorted": (
            list(struct.unpack("<6h", xdata("_sorted", 12))),
            [-3, -3, 0, 5, 7, 12],
        ),
        "r_bsearch_hit": (integer("_r_bsearch_hit"), 4),
        "r_bsearch_miss": (integer("_r_bsearch_miss"), 0),
        "output": (output, "done\n51\n"),
    }
    if models:
        checks["models not run"] = (
            sorted(set(_LIBC_FUNCTIONS.values()) - called),
            [],
        )
    return _report(checks, [])


def _run_interrupts(smallworld, engine: str) -> int:
    platform, machine, code = _setup(
        smallworld, _DIR / "interrupts.cip51.mcs51", "C8051F330", emulate_device=True
    )
    emulator = make_emulator(smallworld, platform, engine)
    emulator.add_exit_point(_program_exit(code))
    machine.emulate(emulator)

    count = emulator.read_memory(code.get_symbol_value("_n"), 1)[0]
    order = list(emulator.read_memory(code.get_symbol_value("_order"), count))
    # Handlers log their interrupt numbers, main its markers, 0xF0 and up.
    checks = {
        "order": (
            order,
            [6, 7, 10, 14, 0xF0]  # IE and EIE1 sources, in polling order
            + [14, 6, 0xF1]  # EIP1 priority beats polling order
            + [7, 14, 0x70, 0xF2]  # high priority nests in low
            + [0xF3, 5, 0xF4]  # TF2L gated by TF2LEN
            + [0xF5, 11, 0xF6]  # CCF1 gated by ECCF1
            + [0xF7, 12, 0xF8],  # CP0RIF gated by CP0RIE
        ),
    }
    return _report(checks, [])


def _run_flash(smallworld, engine: str) -> int:
    from smallworld.platforms.defs.mcs51 import MCS51_CODE_BASE, MCS51_XDATA_BASE

    platform, machine, code = _setup(
        smallworld, _DIR / "flash.cip51.mcs51", "C8051F330", emulate_device=True
    )
    # The flash page the program erases and writes, past its code.
    page = 0x1A00
    machine.add(
        smallworld.state.memory.RawMemory.from_bytes(
            bytes(0x200), MCS51_CODE_BASE + page
        )
    )
    emulator = make_emulator(smallworld, platform, engine)
    emulator.add_exit_point(_program_exit(code))
    machine.emulate(emulator)

    result = list(emulator.read_memory(code.get_symbol_value("_result"), 12))
    checks = {
        # FLKEY: first key, unlocked, locked after the erase; disabled after
        # a write while locked, and still after the keys.
        "flkey": (result[:5], [1, 2, 0, 3, 3]),
        # Flash at 0x1A00-0x1A04, 0x1A10 and 0x1BFF: 0x5A & 0x0F, 0xC3, and
        # erased bytes the locked writes left alone.
        "flash": (result[5:12], [0x0A, 0xC3, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]),
        "xdata": (
            list(emulator.read_memory(MCS51_XDATA_BASE + page, 5))
            + list(emulator.read_memory(MCS51_XDATA_BASE + page + 0x10, 1)),
            [0, 0, 0, 0, 0x77, 0],
        ),
    }
    return _report(checks, [])


def _run_flash_efm8bb2(smallworld, engine: str) -> int:
    from smallworld.platforms.defs.mcs51 import MCS51_CODE_BASE

    platform, machine, code = _setup(
        smallworld,
        _DIR / "flash_efm8bb2.efm8bb2.mcs51",
        "EFM8BB21F16G",
        emulate_device=True,
    )
    # The pages the program erases, and their neighbors, all zero.
    for start, size in ((0x1800, 0x600), (0xF800, 0x400)):
        machine.add(
            smallworld.state.memory.RawMemory.from_bytes(
                bytes(size), MCS51_CODE_BASE + start
            )
        )
    emulator = make_emulator(smallworld, platform, engine)
    emulator.add_exit_point(_program_exit(code))
    machine.emulate(emulator)

    result = list(emulator.read_memory(code.get_symbol_value("_result"), 10))
    checks = {
        # 0x19FF, 0x1A00, 0x1BFF and 0x1C00: the 512-byte page at 0x1A00.
        "large page": (result[:4], [0, 0xFF, 0xFF, 0]),
        # 0xF83F, 0xF840, 0xF845, 0xF87F and 0xF880: the 64-byte page at
        # 0xF840, with 0x3C written at 0xF845.
        "small page": (result[4:9], [0, 0xFF, 0x3C, 0xFF, 0]),
        "flkey": (result[9], 0),
    }
    return _report(checks, [])


def _sfrpages_checks(xdata) -> Dict[str, Tuple[Any, Any]]:
    # sfrpages.c's results, for the C8051F040, F060 and F120.
    return {
        # RCAP2L, RCAP3L and RCAP4L, all at 0xCA, on pages 0, 1 and 2.
        "pages": (xdata("_result", 3), [0x20, 0x31, 0x42]),
        # TR2 set in TMR2CN, and P4_3 in P4, both at 0xC8, on pages 0, 0x0F.
        "bits": (xdata("_result", 5)[3:], [0x04, 0x08]),
        "shared": (xdata("_result", 6)[5], 0x5A),
        "pop": (xdata("_result", 7)[6], 0x31),
        "after reti": (xdata("_result", 8)[7], 1),
        # With the page stack, Timer 0's handler is on page 0, main's page,
        # 1, in SFRNEXT; without, on main's page, with SFRNEXT as RETI left
        # it, SFRLAST's 0.
        "handler pages": (xdata("_isr", 4), [0, 1, 1, 0]),
        "handlers": (xdata("_isr_count", 1)[0], 4),
    }


def _sfrpages_f36x_checks(xdata) -> Dict[str, Tuple[Any, Any]]:
    # sfrpages_f36x.c's results, for the C8051F360.
    result = xdata("_result", 4)
    return {
        # MAC0AL and P0MDOUT, both at 0xA4, on pages 0 and 0x0F.
        "pages": (result[:2], [0x12, 0x34]),
        "shared": (result[2], 0x5A),
        "after reti": (result[3], 0x0F),
        # With the page stack, Timer 0's handler is on page 0, main's page,
        # 0x0F, in SFRNEXT; without, on main's page, with SFRNEXT as RETI
        # left it, SFRLAST's 0.
        "handler pages": (xdata("_isr", 4), [0, 0x0F, 0x0F, 0]),
        "handlers": (xdata("_isr_count", 1)[0], 4),
    }


_SFRPAGES_CHECKS = {
    "sfrpages": _sfrpages_checks,
    "sfrpages_f36x": _sfrpages_f36x_checks,
}


def _run_sfrpages(smallworld, program: str, build: str, engine: str) -> int:
    device, emulate_device = _DEVICES[build]
    platform, machine, code = _setup(
        smallworld, _DIR / f"{program}.{build}.mcs51", device, emulate_device
    )
    emulator = make_emulator(smallworld, platform, engine)
    emulator.add_exit_point(_program_exit(code))
    machine.emulate(emulator)

    def xdata(name: str, size: int) -> List[int]:
        return list(emulator.read_memory(code.get_symbol_value(name), size))

    return _report(_SFRPAGES_CHECKS[program](xdata), [])


def run_case(scenario: str, variant: str, args: Sequence[str]) -> int:
    import smallworld

    _, program, build = scenario.split(".")
    _, engine = split_variant(variant)
    smallworld.logging.setup_logging(level=logging.INFO)
    if program == "abi":
        return _run_abi(smallworld, build, engine)
    if program == "interrupts":
        return _run_interrupts(smallworld, engine)
    if program == "flash":
        return _run_flash(smallworld, engine)
    if program == "flash_efm8bb2":
        return _run_flash_efm8bb2(smallworld, engine)
    if program in _SFRPAGES_CHECKS:
        return _run_sfrpages(smallworld, program, build, engine)
    return _run_libc(smallworld, build, engine, models=program == "libc_models")
