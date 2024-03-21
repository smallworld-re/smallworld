import argparse
import copy
import typing

from . import analyses, emulators, state

T = typing.TypeVar("T", bound=state.CPU)


def emulate(cpu: T) -> T:
    """Emulate execution of some code.

    Arguments:
        cpu: A state class from which emulation should begin.

    Returns:
        The final cpu of the system.
    """

    # only support Unicorn for now
    emu = emulators.UnicornEmulator(cpu.arch, cpu.mode)

    cpu.apply(emu)

    emu.run()

    cpu = copy.deepcopy(cpu)
    cpu.load(emu)

    return cpu


def analyze(cpu: T) -> None:
    """Run all available analyses on some code.

    All analyses are run with default parameters.

    Arguments:
        cpu: A state class from which emulation should begin.
    """

    for name in analyses.__all__:
        module: typing.Type = getattr(analyses, name)
        if issubclass(module, analyses.Filter) and module is not analyses.Filter:
            module().activate()

    for name in analyses.__all__:
        module = getattr(analyses, name)
        if issubclass(module, analyses.Analysis) and module is not analyses.Analysis:
            module().run(cpu)


def fuzz(
    cpu: T,
    input_callback: typing.Callable,
    fuzzing_callback: typing.Optional[typing.Callable] = None,
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
        fuzzing_callback: This is for "more complex fuzzing logic", no idea
            what that means.
        crash_callback: This is called on crashes to validate that we do in
            fact care about this crash.
        always_validate: Call the crash_callback everytime instead of just on
            crashes.
        iterations: How many iterations to run before forking again.
    """

    try:
        from unicornafl import uc_afl_fuzz, uc_afl_fuzz_custom
    except ImportError:
        raise RuntimeError(
            "missing `unicornafl` - is the `fuzzing` extra enabled? (`pip install smallworld[fuzzing]`)"
        )

    arg_parser = argparse.ArgumentParser(description="AFL Harness")
    arg_parser.add_argument("input_file", type=str, help="File path AFL will mutate")
    args = arg_parser.parse_args()

    emu = emulators.UnicornEmulator(cpu.arch, cpu.mode)
    cpu.apply(emu)

    if fuzzing_callback:
        uc_afl_fuzz_custom(
            uc=emu.engine,
            input_file=args.input_file,
            place_input_callback=input_callback,
            fuzzing_callback=fuzzing_callback,
            validate_crash_callback=crash_callback,
            always_validate=always_validate,
            persistent_iters=iterations,
        )
    else:
        exits = []
        for _, code in cpu.values(state.Code).items():
            exits.extend(code.exits)

        if len(exits) == 0:
            exits.append(code.base + len(code.image))

        uc_afl_fuzz(
            uc=emu.engine,
            input_file=args.input_file,
            place_input_callback=input_callback,
            exits=exits,
            validate_crash_callback=crash_callback,
            always_validate=always_validate,
            persistent_iters=iterations,
        )
