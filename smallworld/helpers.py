import copy
import typing

from . import analyses, emulators, state

T = typing.TypeVar("T", bound=state.CPU)


def emulate(state: T) -> T:
    """Emulate execution of some code.

    Arguments:
        state: A state class from which emulation should begin.

    Returns:
        The final state of the system.
    """

    # only support Unicorn for now
    emu = emulators.UnicornEmulator(state.arch, state.mode)

    state.apply(emu)

    emu.run()

    state = copy.deepcopy(state)
    state.load(emu)

    return state


def analyze(state: T) -> None:
    """Run all available analyses on some code.

    All analyses are run with default parameters.

    Arguments:
        state: A state class from which emulation should begin.
    """

    for name in analyses.__all__:
        module: typing.Type = getattr(analyses, name)
        if issubclass(module, analyses.Filter) and module is not analyses.Filter:
            module().activate()

    for name in analyses.__all__:
        module = getattr(analyses, name)
        if issubclass(module, analyses.Analysis) and module is not analyses.Analysis:
            module().run(state)
