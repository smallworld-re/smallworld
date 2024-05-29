import pypcode

from .. import state


class PcodeCPUState(state.CPU):
    """Abstract auto-populated CPU state built using pcode defs

    Ghidra's language defs lay out registers in a register file.
    This is enough to identify individual registers and their aliases.

    Specific implementations should initialize the parent
    with a specific language, and specify the capstone arch and mode.

    Arguments:
        language: Pcode language ID.
    """

    def __init__(self, language: str):
        ctx = pypcode.Context(language)
        regs = list(map(lambda x: (x[1], x[0]), ctx.registers.items()))

        # Sort registers in increasing order of offset,
        # secondary-sorted by decreasing size.
        # This makes the next step hugely more efficient.
        regs.sort(key=lambda x: (x[0].offset << 32) + (2**32 - x[0].size))

        curr = None
        curr_model = None
        for reg, name in regs:
            if curr is None or reg.offset >= curr.offset + curr.size:
                # We've moved out of the region covered by the current register.
                # Our next register is the new base register.

                curr = reg
                curr_model = state.Register(name, width=reg.size)
                setattr(self, name, curr_model)
            else:
                # We're still "inside" another register.
                # This is an alias
                setattr(
                    self,
                    name,
                    state.RegisterAlias(
                        name,
                        curr_model,
                        width=reg.size,
                        offset=reg.offset - curr.offset,
                    ),
                )


class Sparc64CPUState(PcodeCPUState):
    arch = "sparc"
    mode = "v9"

    def __init__(self):
        super().__init__("sparc:BE:64:default")
