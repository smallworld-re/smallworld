from ....platforms import Architecture, Byteorder
from .machdef import GhidraMachineDef


class MSP430AbsMachineDef(GhidraMachineDef):
    byteorder = Byteorder.LITTLE

    _registers = {
        "pc": "PC",
        "r0": "PC",
        "sp": "SP",
        "r1": "SP",
        "sr": "SR",
        "r2": "SR",
        # NOTE: cg1 isn't accessible directly.
        # Accessing the constant generator registers is somewhat meaningless,
        # so this isn't a hardship.
        "cg1": None,
        "cg2": "R3",
        "r3": "R3",
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


class MSP430MachineDef(MSP430AbsMachineDef):
    arch = Architecture.MSP430

    language_id = "TI_MSP430:LE:16:default"


class MSP430XMachineDef(MSP430AbsMachineDef):
    arch = Architecture.MSP430X

    language_id = "TI_MSP430X:LE:32:default"
