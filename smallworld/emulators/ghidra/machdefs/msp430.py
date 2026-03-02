from ....platforms import Architecture, Byteorder
from .machdef import GhidraMachineDef


class MSP430MachineDef(GhidraMachineDef):
    arch = Architecture.MSP430
    byteorder = Byteorder.LITTLE

    language_id = "TI_MSP430:LE:16:default"

    _registers = {
        "pc": "PC",
        "sp": "SP",
        "sr": "SR",
        # NOTE: cg1 isn't accessible directly.
        # Accessing the constant generator registers is somewhat meaningless,
        # so this isn't a hardship.
        "cg1": None,
        "cg2": "R3",
        "r4": "R4",
        "r5": "R5",
        "r6": "R6",
        "r7": "R7",
        "r8": "R8",
        "r9": "R9",
        "r10": "R10",
        "r11": "R11",
        "r12": "R12",
        "r13": "R13",
        "r14": "R14",
        "r15": "R15",
    }
