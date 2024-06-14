import argparse
import logging
import typing

logger = logging.getLogger(__name__)


from . import analyses, emulators, state

T = typing.TypeVar("T", bound=state.CPU)


def analyze(cpu: T) -> None:
    """Run all available analyses on some code.

    All analyses are run with default parameters.

    Arguments:
        cpu: A state class from which emulation should begin.
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
                module().run(cpu)
    finally:
        for filter in filters:
            filter.deactivate()


def fuzz(
    cpu: T,
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

    emu = emulators.UnicornEmulator(cpu.arch, cpu.mode)
    cpu.apply(emu)

    exits = []
    for _, code in cpu.members(state.Code).items():
        exits.extend([b.stop for b in code.bounds])

    if len(exits) == 0:
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


def setup_default_libc(
    flat_api: typing.Any,
    elf_file: str,
    libc_func_names: typing.List[str],
    cpustate: state.CPU,
) -> None:
    """Map some default libc models into the cpu state.

    Uses Ghdira to figure out entry points in PLT for libc fns and arranges for
    those in a user-provided list to be hooked using the default models in
    Smallworld.  Idea is you might not want all of them mapped and so you say
    just these for now.

    Arguments:
        flat_api: this is what gets returned by pyhidra.open_program(elf_file)
        libc_func_names: list of names of libc functions
        cpustate: cpu state into which to map models
    """

    program = flat_api.getCurrentProgram()
    listing = program.getListing()

    # find plt section
    plt = None
    for block in program.getMemory().getBlocks():
        if "plt" in block.getName():
            plt = block

    assert plt is not None

    # map all requested libc default models
    num_mapped = 0
    num_no_model = 0
    num_too_many_models = 0
    for func in listing.getFunctions(True):
        func_name = func.getName()
        entry = func.getEntryPoint()
        if plt.contains(entry) and func_name in libc_func_names:  # type: ignore
            # func is in plt and it is a function for which we want to use a default model
            int_entry = int(entry.getOffset())
            ml = state.models.get_models_by_name(
                func_name, state.models.AMD64SystemVImplementedModel
            )
            # returns list of models. for now we hope there's either 1 or 0...
            if len(ml) == 1:
                class_ = ml[0]
                # class_ = getattr(state.models, cls_name)
                cpustate.map(class_(int_entry))
                logger.debug(f"Added libc model for {func_name} entry {int_entry:x}")
                num_mapped += 1
            elif len(ml) > 1:
                logger.debug(
                    f"XXX There are {len(ml)} models for plt fn {func_name}... ignoring bc I dont know which to use"
                )
                num_too_many_models += 1
            else:
                logger.debug(
                    f"As there is no default model for {func_name}, adding with null model, entry {int_entry:x}"
                )
                cpustate.map(state.models.AMD64SystemVNullModel(int_entry))
                num_no_model += 1

    logger.info(
        f"Libc model mappings: {num_mapped} default, {num_no_model} no model, {num_too_many_models} too many models"
    )
