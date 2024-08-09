import argparse
import logging
import typing
import pdb
from ast import literal_eval
import pefile

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

    emu = emulators.UnicornEmulator(cpu.arch, cpu.mode, cpu.byteorder)
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
    libc_func_names: typing.List[str],
    cpustate: state.CPU,
    canonicalize: bool = True,
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
        if not plt.contains(entry):
            continue
        else:
            if func_name in libc_func_names:  # type: ignore
                # func is in plt and it is a function for which we want to use a default model
                int_entry = int(entry.getOffset())
                ml = state.models.get_models_by_name(
                    func_name, state.models.AMD64SystemVImplementedModel
                )
                # returns list of models. for now we hope there's either 1 or 0...
                if len(ml) == 1:
                    model_class = ml[0]
                    ext_func_model = model_class(int_entry)
                    cpustate.map(ext_func_model, func_name)
                    logger.debug(
                        f"Added libc model {ext_func_model} for {func_name} entry {int_entry:x}"
                    )
                    num_mapped += 1
                elif len(ml) > 1:
                    logger.error(
                        f"XXX There are {len(ml)} models for plt fn {func_name}... ignoring bc I dont know which to use"
                    )
                    num_too_many_models += 1
                else:
                    logger.error(
                        f"XXX As there is no default model for {func_name}, adding with null model, entry {int_entry:x}"
                    )
                    cpustate.map(
                        state.models.AMD64SystemVNullModel(int_entry), func_name
                    )
                    num_no_model += 1

    logger.info(
        f"Libc model mappings: {num_mapped} default, {num_no_model} no model, {num_too_many_models} too many models"
    )

vector_patterns =  [
    "std::vector<int>::vector",
    "std::vector<int>::~vector",
    "std::vector<int>::push_back",
    "std::vector<int>::insert",
    "std::vector<int>::clear",
    "std::vector<int>::resize",
    "std::vector<int>::begin",
    "std::vector<int>::end"]


def setup_default_windows(
    flat_api: typing.Any,
    windows_func_names: typing.List[str],
    cpustate: state.CPU,
    pef: str,
    canonicalize: bool = True,
) -> None:
    """Map some default libc models into the cpu state.

    Uses Ghidra to figure out entry points for windows fns and arranges for
    those in a user-provided list to be hooked using the default models in
    Smallworld.  Idea is you might not want all of them mapped and so you say
    just these for now.

    Arguments:
        flat_api: this is what gets returned by pyhidra.open_program(elf_file)
        windows_func_names: list of names of windows functions
        cpustate: cpu state into which to map models
    """

    program = flat_api.getCurrentProgram()
    #flat_api.analyzeAll(program)
    listing = program.getListing()
    #symbol_table = program.getSymbolTable()

    # find iat section
    iat = None
    text = None

    for block in program.getMemory().getBlocks():
        if ".idata" in block.getName():
            iat = block
        if ".text" in block.getName():
            text = block

    assert iat is not None
    assert text is not None

    # for func in listing.getFunctions(True):
    #     if literal_eval('0x' + func.entryPoint.toString()) == 0x140001992:
    #         pdb.set_trace()

    # for instr in listing.getInstructions(text.start, True):
    #     if literal_eval('0x' + instr.address.toString()) == 0x1400064a1:
    #     #if instr.address.toString() == 'EXTERNAL:00000029':
    #         pdb.set_trace()
                    
    # for symbol in symbol_table.getAllSymbols(True):
    #     if symbol.external:
    #         continue
    #     mangled_name = symbol.getName()
    #     if "?" in mangled_name:
    #         demangled_obj = demangler.demangle(mangled_name)
    #         logger.debug(demangled_obj)
    #         pdb.set_trace()

    # map all requested windows models
    num_mapped = 0
    num_no_model = 0
    num_too_many_models = 0

    for func in listing.getExternalFunctions():
        fn_name = func.getName()
        ref = flat_api.getReferencesTo(func.getEntryPoint())[0]
        
        if not iat.contains(ref.fromAddress):
            continue
        if fn_name in windows_func_names:
            #pdb.set_trace()
            ml = state.models.get_models_by_name(
                fn_name, state.models.AMD64MicrosoftImplementedModel
            )
            entry = '0x' + ref.fromAddress.toString()
            #pdb.set_trace()
            int_entry = literal_eval(entry)
            if len(ml) == 1:
                model_class = ml[0]
                ext_func_model = model_class(int_entry)
                #pdb.set_trace()
                cpustate.map(ext_func_model, fn_name)
                logger.debug(f"Added windows model {ext_func_model} for {fn_name} at {int_entry:x}")
                #pdb.set_trace()
                num_mapped += 1
            elif len(ml) > 1:
                logger.error(f"XXX There are {len(ml)} models for function {fn_name}, ignoring.")
                num_too_many_models += 1
            else:
                logger.error(f"XXX As there is no default model for function {fn_name}, adding null model.")
                cpustate.map(state.models.AMD64MicrosoftNullModel(int_entry), fn_name)
                num_no_model += 1


def setup_section(
    flat_api: typing.Any, section_name: str, cpustate: state.CPU, elf_file: str = "None"
) -> bytes:
    """Set up this section in cpustate, possibly using contents of elf file

    Uses ghidra to get start addr / size of sections for adding them to
    cpustate. If elf_file is specified, the data will come from the file (ghidra
    tells us where to find it) and get mapped into cpustate memory. Else that
    will be zeros.

    Arguments:
        flat_api: this is what gets returned by pyhidra.open_program(elf_file)
        section_name: '.data' or '.txt' or '.got' or ..
        cpustate: cpu state into which to map models
        elf_file: name of file flat_api came from (elf)

    Returns:
        If elf_file is specified then cpu state for that came from
        file which means we loaded the data out of the file at the
        correct offset.  This will be returned in that case. Else, the
        section data will be 0s.

    """
    # note, elf_file assumed to be same as one flat_api opened
    program = flat_api.getCurrentProgram()
    memory = program.getMemory()
    block = memory.getBlock(section_name)
    address = int(block.start.getOffset())
    size = int(block.size)
    section_bytes = None
    if elf_file == "None":
        # assume we are to just zero this
        section_bytes = b"\0" * size
    else:
        # this is file offset that block
        offs_in_elf = block.getSourceInfos()[0].getFileBytesOffset()
        # read actual section bytesout of elf
        with open(elf_file, "rb") as e:
            e.seek(offs_in_elf)
            section_bytes = e.read(size)
    section = state.Memory(address=address, size=size)
    section.value = section_bytes
    cpustate.map(section, section_name)
    return section_bytes
