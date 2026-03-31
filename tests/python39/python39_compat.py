from importlib import metadata
import logging

import smallworld


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


def main() -> None:
    smallworld.logging.setup_logging(level=logging.INFO)
    version = metadata.version("smallworld-re")
    print(f"Python 3.9.6 smoke test using smallworld-re {version}")

    run_case(100, 1)
    run_case(7, 0)


if __name__ == "__main__":
    main()
