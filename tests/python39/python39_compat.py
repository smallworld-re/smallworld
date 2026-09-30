import logging
import pathlib
import pickle
import sys
from importlib import metadata

import smallworld
from smallworld.platforms import abi


def run_case(input_arg: int, expected: int) -> None:
    platform = smallworld.platforms.Platform(
        smallworld.platforms.Architecture.POWERPC32,
        smallworld.platforms.Byteorder.BIG,
    )

    machine = smallworld.state.Machine()
    cpu = smallworld.state.cpus.CPU.for_platform(platform)
    machine.add(cpu)

    # Compare r3 against 100 and set it to 1 if equal, otherwise 0.
    raw_bytes = (
        b"\x2c\x03\x00\x64\x40\x82\x00\x0c\x38\x60\x00\x01"
        b"\x48\x00\x00\x08\x38\x60\x00\x00\x60\x00\x00\x00"
    )
    code = smallworld.state.memory.code.Executable.from_bytes(raw_bytes, address=0x1000)
    machine.add(code)

    cpu.pc.set(code.address)
    cpu.r3.set(input_arg)
    machine.add_exit_point(code.address + code.get_capacity())

    unicorn = smallworld.emulators.UnicornEmulator(platform)
    result = machine.emulate(unicorn)
    actual = result.get_cpu().r3.get()

    if actual != expected:
        raise AssertionError(f"expected r3={expected}, got r3={actual}")


def run_abi_case() -> None:
    # The shipped ABI tables are generated at build time; serve the unit
    # tests' hand-written fixture records instead.
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
    from abi import fixtures

    # Python 3.9 builds generate no ABI tables: none load, the tables declare
    # no features, and every lookup raises ABITablesUnavailable.
    # API_FEATURES describes the code, not the tables.
    if abi.tables_available() or abi.table_features() != frozenset():
        raise AssertionError("unexpected ABI tables on Python 3.9")
    if not isinstance(abi.API_FEATURES, frozenset):
        raise AssertionError(f"unexpected API_FEATURES {abi.API_FEATURES!r}")
    try:
        abi.maybe_resolve(fixtures.X86_64)
    except abi.ABITablesUnavailable:
        pass
    else:
        raise AssertionError("maybe_resolve without tables did not raise")
    with abi.registry._use_records(fixtures.RECORDS):
        sysv = abi.resolve(fixtures.X86_64)
        a64 = abi.resolve(fixtures.AARCH64)
        checks = [
            (sysv.int_arg_registers(), ("rdi", "rsi", "rdx", "rcx", "r8", "r9")),
            (sysv.callee_saved_values(), ("rbx", "r12", "r13", "r14", "r15", "rbp")),
            (sysv.is_callee_saved("ebx"), True),
            (a64.is_callee_saved("d8"), True),
            (a64.is_callee_saved_value("d8"), False),
            (a64.is_caller_saved("q8"), True),
            (pickle.loads(pickle.dumps(a64)) is a64, True),
            (abi.validate.check_records(fixtures.RECORDS), ()),
        ]
        for actual, expected in checks:
            if actual != expected:
                raise AssertionError(f"expected {expected!r}, got {actual!r}")


def main() -> None:
    smallworld.logging.setup_logging(level=logging.INFO)
    version = metadata.version("smallworld-re")
    print(f"Python 3.9.6 smoke test using smallworld-re {version}")

    run_case(100, 1)
    run_case(7, 0)
    run_abi_case()


if __name__ == "__main__":
    main()
