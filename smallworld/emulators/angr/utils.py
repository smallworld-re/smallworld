import logging

from ...exceptions import AnalysisError

log = logging.getLogger(__name__)


def reg_name_from_offset(arch, addr: int, size: int):
    """Get a register name from its offset and size in the register file

    This should be straightforward, and it is for standard architectures.

    Architectures supported via pcode have a nasty quirk
    where register down-casts happen before reading the register.
    This means angr can't tell the difference between a real sub-register,
    or a read from part of a larger register.
    This has the effect of selecting incorrect sub-registers,
    or hallucinating non-existent sub-registers.

    This function does a bit of searching to try
    and match the specified address/size to the closest register.

    Arguments:
        arch:   angr architecture object
        addr:   address of register write
        size:   size of register write

    Returns:
        A string containing the register name

    Raises:
        AnalysisException: If no matching register is found

    """
    orig_size = size
    done = False

    if (addr, size) in arch.register_size_names:
        # We have an exact match.
        # Don't bother with other checks.
        done = True
    else:
        # Check if we're accessing the tail of a larger register.
        for r_addr, r_size in arch.register_size_names:
            if addr == r_addr + r_size - size:
                addr = r_addr
                size = r_size
                done = True
                break

    # Hypothesize we're accessing the head of a larger register
    # TODO: This assumes power-of-two-sized registers
    #
    # I know this isn't accurate for some architectures.
    # It also won't be accurate if the sleigh model
    # includes non-power-of-two extractions.
    #
    # TODO: Do any architectures have registers larger than 512 bits?
    # If they do, I'm very sorry.
    while not done and size < 1024:
        if (addr, size) in arch.register_size_names:
            done = True
            break

        if not done:
            size = size << 1

    if not done:
        raise AnalysisError(f"Unknown register for {arch.name}: ({addr}, {orig_size})")
    return arch.register_size_names[(addr, size)]
