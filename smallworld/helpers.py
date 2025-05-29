import argparse
import logging
import typing

logger = logging.getLogger(__name__)


from . import analyses, emulators, exceptions, state

T = typing.TypeVar("T", bound=state.Machine)


def analyze(
    machine: state.Machine,
    asys: typing.List[typing.Union[analyses.Analysis, analyses.Filter]],
) -> None:
    """Run requested analyses on some code

    Arguments:
        machine: A state class from which emulation should begin.
        asys: List of analyses and filters to run
    """

    filters: typing.List[analyses.Filter] = []
    runners: typing.List[analyses.Analysis] = []
    for analysis in asys:
        if isinstance(analysis, analyses.Filter):
            filters.append(analysis)
            filters[-1].activate()
        elif isinstance(analysis, analyses.Analysis):
            runners.append(analysis)

    try:
        for analysis in runners:
            analysis.run(machine)
    except:
        logger.exception("Error durring analysis")
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
