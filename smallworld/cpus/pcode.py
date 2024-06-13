import typing

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

    SYNTHETIC_REGS: typing.List[str] = []

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
            if name in self.SYNTHETIC_REGS:
                # This register is marked as an artifact of Sleigh.
                # Don't actually include it in the model.
                continue
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
    endian = "big"

    # Sparc64 uses register windows.
    # The sleigh model maintains a set of registers for the current window
    # and a backing bank of registers for saving inactive windows.
    #
    # Each inactive window needs 16 register slots:
    # 8 for the 'iX' registers, 8 for the 'lX' registers.
    #
    # In theory, the inactive window registers
    # should be named wXYZ, where X is the window number,
    # Y indicates input, local, or output,
    # and Z is the register number.
    # At some point in the past, the Sleigh model authors
    # realized you didn't need to save the output registers,
    # so the windows no longer line up with the names after window 0.
    #
    # A few registers in a window are not general:
    # - g0: Always bound to 0
    # - i6: frame pointer
    # - o6: stack pointer
    # - i7/o7: link registers
    GENERAL_PURPOSE_REGS = [
        # Globals: These are shared across everything
        "g1",
        "g2",
        "g3",
        "g4",
        "g5",
        "g6",
        "g7",
        # Current window registers
        "i0",
        "i1",
        "i2",
        "i3",
        "i4",
        "i5",
        "o0",
        "o1",
        "o2",
        "o3",
        "o4",
        "o5",
        "l0",
        "l1",
        "l2",
        "l3",
        "l4",
        "l5",
        "l6",
        "l7",
        # Window 0 registers
        "w010",  # i0
        "w011",  # i1
        "w012",  # i2
        "w013",  # i3
        "w014",  # i4
        "w015",  # i5
        "w020",  # l0
        "w021",  # l1
        "w022",  # l2
        "w023",  # l3
        "w024",  # l0
        "w025",  # l1
        "w026",  # l2
        "w027",  # l3
        # Window 1 registers
        "w030",  # i0
        "w031",  # i1
        "w032",  # i2
        "w033",  # i3
        "w034",  # i4
        "w035",  # i5
        "w110",  # l0
        "w111",  # l1
        "w112",  # l2
        "w113",  # l3
        "w114",  # l0
        "w115",  # l1
        "w116",  # l2
        "w117",  # l3
        # Window 2 registers
        "w120",  # i0
        "w121",  # i1
        "w122",  # i2
        "w123",  # i3
        "w124",  # i4
        "w125",  # i5
        "w130",  # l0
        "w131",  # l1
        "w132",  # l2
        "w133",  # l3
        "w134",  # l0
        "w135",  # l1
        "w136",  # l2
        "w137",  # l3
        # Window 3 registers
        "w210",  # i0
        "w211",  # i1
        "w212",  # i2
        "w213",  # i3
        "w214",  # i4
        "w215",  # i5
        "w220",  # l0
        "w221",  # l1
        "w222",  # l2
        "w223",  # l3
        "w224",  # l0
        "w225",  # l1
        "w226",  # l2
        "w227",  # l3
        # Window 4 registers
        "w230",  # i0
        "w231",  # i1
        "w232",  # i2
        "w233",  # i3
        "w234",  # i4
        "w235",  # i5
        "w310",  # l0
        "w311",  # l1
        "w312",  # l2
        "w313",  # l3
        "w314",  # l0
        "w315",  # l1
        "w316",  # l2
        "w317",  # l3
        # Window 5 registers
        "w320",  # i0
        "w321",  # i1
        "w322",  # i2
        "w323",  # i3
        "w324",  # i4
        "w325",  # i5
        "w330",  # l0
        "w331",  # l1
        "w332",  # l2
        "w333",  # l3
        "w334",  # l0
        "w335",  # l1
        "w336",  # l2
        "w337",  # l3
        # Window 6 registers
        "w400",  # i0
        "w401",  # i1
        "w402",  # i2
        "w403",  # i3
        "w404",  # i4
        "w405",  # i5
        "w410",  # l0
        "w411",  # l1
        "w412",  # l2
        "w413",  # l3
        "w414",  # l0
        "w415",  # l1
        "w416",  # l2
        "w417",  # l3
        # Window 7 registers
        "w420",  # i0
        "w421",  # i1
        "w422",  # i2
        "w423",  # i3
        "w424",  # i4
        "w425",  # i5
        "w430",  # l0
        "w431",  # l1
        "w432",  # l2
        "w433",  # l3
        "w434",  # l0
        "w435",  # l1
        "w436",  # l2
        "w437",  # l3
        # Window 8 registers
        "w510",  # i0
        "w511",  # i1
        "w512",  # i2
        "w513",  # i3
        "w514",  # i4
        "w515",  # i5
        "w520",  # l0
        "w521",  # l1
        "w522",  # l2
        "w523",  # l3
        "w524",  # l0
        "w525",  # l1
        "w526",  # l2
        "w527",  # l3
        # Window 9 registers
        "w530",  # i0
        "w531",  # i1
        "w532",  # i2
        "w533",  # i3
        "w534",  # i4
        "w535",  # i5
        "w610",  # l0
        "w611",  # l1
        "w612",  # l2
        "w613",  # l3
        "w614",  # l0
        "w615",  # l1
        "w616",  # l2
        "w617",  # l3
        # Window 10 registers
        "w620",  # i0
        "w621",  # i1
        "w622",  # i2
        "w623",  # i3
        "w624",  # i4
        "w625",  # i5
        "w630",  # l0
        "w631",  # l1
        "w632",  # l2
        "w633",  # l3
        "w634",  # l0
        "w635",  # l1
        "w636",  # l2
        "w637",  # l3
        # Window 11 registers
        "w710",  # i0
        "w711",  # i1
        "w712",  # i2
        "w713",  # i3
        "w714",  # i4
        "w715",  # i5
        "w720",  # l0
        "w721",  # l1
        "w722",  # l2
        "w723",  # l3
        "w724",  # l0
        "w725",  # l1
        "w726",  # l2
        "w727",  # l3
    ]

    def __init__(self):
        super().__init__("sparc:BE:64:default")
