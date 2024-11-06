import logging
import typing

from ... import platforms, state

# TODO fix these imports after refactoring state module
# from ... import models, state

logger = logging.getLogger(__name__)


# TODO: fix the cpustate type label once refactoring state module is complete
def setup_default_libc(
    flat_api: typing.Any,
    libc_func_names: typing.List[str],
    cpustate: typing.Any,
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

    platform = platforms.Platform(
        platforms.Architecture.X86_64, platforms.Byteorder.LITTLE
    )
    abi = platforms.ABI.SYSTEMV

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
                try:
                    # func is in plt and it is a function for which we want to use a default model
                    int_entry = int(entry.getOffset())
                    model = state.models.Model.lookup(
                        func_name, platform, abi, int_entry
                    )
                    cpustate.map(model)
                    logger.debug(
                        f"Added libc model for {func_name} entry {int_entry:x}"
                    )
                    num_mapped += 1
                except ValueError:
                    logger.debug(
                        f"As there is no default model for {func_name}, adding with null model, entry {int_entry:x}"
                    )
                    model = state.models.Model.lookup("null", platform, abi, int_entry)
                    cpustate.map(model)
                    num_no_model += 1

    logger.info(
        f"Libc model mappings: {num_mapped} default, {num_no_model} no model, {num_too_many_models} too many models"
    )


# TODO: fix the cpustate type label once refactoring state module is complete
def setup_section(
    flat_api: typing.Any,
    section_name: str,
    cpustate: typing.Any,
    elf_file: str = "None",
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
    section = state.memory.RawMemory.from_bytes(section_bytes, address)
    cpustate.map(section, section_name)
    return section_bytes
