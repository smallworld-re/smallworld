import argparse
import copy
import logging
import typing

logger = logging.getLogger(__name__)


from . import analyses, emulators, exceptions, state

T = typing.TypeVar("T", bound=state.Machine)


def analyze(
    machine: state.Machine,
    asys: typing.List[analyses.Analysis],
) -> None:
    """Run requested analyses on some code

    Arguments:
        machine: A state class from which emulation should begin.
        asys: List of analyses and filters to run
    """
    for a in asys:
        a.run(copy.deepcopy(machine))


def _fuzz_exit_points(machine: state.Machine) -> typing.List[int]:
    """Derive the exit addresses for a fuzzing run from a machine's code.

    Each Executable contributes its end address(es): loader-built code (elf/pe/
    vxworks/...) exposes a ``bounds`` RangeCollection of its loaded segments,
    while code added from raw bytes has no ``bounds``, so its single
    ``[address, address + capacity)`` span is used instead.

    Raises:
        ConfigurationError: if the machine contains no code.
    """
    exits: typing.List[int] = []
    saw_code = False
    for code in machine.members(state.memory.code.Executable):
        saw_code = True
        bounds = getattr(code, "bounds", None)
        code_exits = [end for (_start, end) in bounds] if bounds is not None else []
        if not code_exits:
            # Raw-bytes code has no bounds; a loaded image whose bounds happen
            # to be empty likewise falls back to its whole span.
            code_exits = [code.address + code.get_capacity()]
        exits.extend(code_exits)
    if not saw_code:
        raise exceptions.ConfigurationError("Cannot fuzz a machine with no code")
    return exits


def fuzz(
    machine: state.Machine,
    input_callback: typing.Callable,
    crash_callback: typing.Optional[typing.Callable] = None,
    always_validate: bool = False,
    iterations: int = 1,
    engine: str = "unicorn",
) -> None:
    """Creates an AFL fuzzing harness.

    Arguments:
        machine: A state class from which emulation should begin.
        input_callback: This is called for every input. Signature is
            ``(emulator, input_bytes, persistent_round, data)`` where
            ``emulator`` is the SmallWorld emulator instance regardless of
            which backend is selected. Return ``False`` to skip the input,
            ``None``/``True`` to continue.
        crash_callback: This is called on crashes to validate that we do in
            fact care about this crash.
        always_validate: Call the crash_callback everytime instead of just on
            crashes.
        iterations: How many iterations to run before forking again.
        engine: Which emulator backend to drive the fuzzer with. ``"unicorn"``
            (default) uses unicornafl; ``"styx"`` routes through the Styx
            backend + styxafl bridge.
    """
    arg_parser = argparse.ArgumentParser(description="AFL Harness")
    arg_parser.add_argument("input_file", type=str, help="File path AFL will mutate")
    args = arg_parser.parse_args()

    cpu: typing.Optional[state.cpus.CPU] = None
    for c in machine.members(state.cpus.CPU):
        if cpu is not None:
            raise exceptions.ConfigurationError("cannot fuzz a multi-core machine")
        cpu = c
    if cpu is None:
        raise exceptions.ConfigurationError("cannot fuzz a zero-core machine")

    exits = _fuzz_exit_points(machine)

    if engine == "unicorn":
        emu: emulators.Emulator = emulators.UnicornEmulator(cpu.platform)
    elif engine == "styx":
        emu = emulators.StyxEmulator(cpu.platform)
    else:
        raise exceptions.ConfigurationError(
            f"unknown fuzz engine '{engine}'; expected 'unicorn' or 'styx'"
        )

    for x in exits:
        emu.add_exit_point(x)

    machine.fuzz_with_file(
        emu,
        input_callback,
        args.input_file,
        crash_callback,
        always_validate,
        iterations,
    )


__all__ = ["analyze", "fuzz"]
