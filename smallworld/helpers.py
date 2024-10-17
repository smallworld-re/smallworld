import argparse
import logging
import typing

logger = logging.getLogger(__name__)


from . import analyses, emulators, exceptions, state

T = typing.TypeVar("T", bound=state.Machine)


def analyze(machine: state.Machine) -> None:
    """Run all available analyses on some code.

    All analyses are run with default parameters.

    Arguments:
        machine: A state class from which emulation should begin.
    """

    filters = []
    for name in analyses.__all__:
        module: typing.Type = getattr(analyses, name)
        if issubclass(module, analyses.Filter) and module is not analyses.Filter:
            filters.append(module())
            filters[-1].activate()

    try:
        for name in analyses.__all__:
            module = getattr(analyses, name)
            if (
                issubclass(module, analyses.Analysis)
                and module is not analyses.Analysis
            ):
                module().run(machine)
    finally:
        for filter in filters:
            filter.deactivate()


def fuzz(
    machine: state.Machine,
    input_callback: typing.Callable,
    crash_callback: typing.Optional[typing.Callable] = None,
    always_validate: bool = False,
    iterations: int = 1,
) -> None:
    """Creates an AFL fuzzing harness.

    Arguments:
        cpu: A state class from which emulation should begin.
        input_callback: This is called for every input. It should map the input
            into the state. It should return true if the input is accepted and
            false if it should be skipped.
        crash_callback: This is called on crashes to validate that we do in
            fact care about this crash.
        always_validate: Call the crash_callback everytime instead of just on
            crashes.
        iterations: How many iterations to run before forking again.
    """

    try:
        import unicornafl
    except ImportError:
        raise RuntimeError(
            "missing `unicornafl` - afl++ must be installed manually from source"
        )

    arg_parser = argparse.ArgumentParser(description="AFL Harness")
    arg_parser.add_argument("input_file", type=str, help="File path AFL will mutate")
    args = arg_parser.parse_args()

    cpu: typing.Optional[state.cpus.CPU] = None
    for c in machine.members(state.cpus.CPU).items():
        if cpu is not None:
            raise exceptions.ConfigurationError("cannot fuzz a multi-core machine")
        cpu = c
    if cpu is None:
        raise exceptions.ConfigurationError("cannot fuzz a zero-core machine")

    emu = emulators.UnicornEmulator(cpu.platform)
    machine.apply(emu)

    exits = []
    code = None
    for code in machine.members(state.memory.code.Executable).items():
        exits.extend([b.stop for b in code.bounds])

    if len(exits) == 0:
        if code is None:
            raise exceptions.ConfigurationError("Cannot fuzz a machine with no code")
        exits.append(code.base + len(code.image))

    unicornafl.uc_afl_fuzz(
        uc=emu.engine,
        input_file=args.input_file,
        place_input_callback=input_callback,
        exits=exits,
        validate_crash_callback=crash_callback,
        always_validate=always_validate,
        persistent_iters=iterations,
    )


__all__ = ["analyze"]
