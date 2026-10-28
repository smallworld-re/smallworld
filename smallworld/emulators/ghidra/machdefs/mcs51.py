from ....platforms import Architecture, Byteorder
from ....platforms.defs.mcs51 import MCS51_ADDRESS_SPACES, mcs51_psw_with_parity
from .machdef import GhidraMachineDef, GhidraUserOp


def handle_nop(emulator, op):
    # This op does nothing
    pass


def handle_decimal_adjust(emulator, op):
    # DA A: adjust the accumulator after a BCD addition.  The op returns only
    # the new accumulator; the carry it may set lives in PSW.
    acc = emulator._read_varnode(op.getInputs()[1])
    psw = emulator.read_register("psw")
    carry = bool(psw & 0x80)
    if (acc & 0x0F) > 9 or psw & 0x40:
        acc += 0x06
        carry = carry or acc > 0xFF
    if ((acc >> 4) & 0x0F) > 9 or carry:
        acc += 0x60
        carry = carry or acc > 0xFF
    emulator.write_register("psw", (psw | 0x80) if carry else psw)
    emulator._write_varnode(op.getOutput(), acc)


class MCS51UserOp(GhidraUserOp):
    # Numbered in declaration order.  Ghidra builds the 8051 with
    # BIT_OPS = "BIT_ADDRS", which declares only these two; the bit-access
    # ops (get, set, set_bit_value, clr) exist only under "PCODEOPS".
    DECIMAL_ADJUST = 0x00, "decimal_adjust", handle_decimal_adjust, "Decimal Adjust"
    NOP = 0x01, "nop", handle_nop, "No Operation"


class MCS51MachineDef(GhidraMachineDef):
    arch = Architecture.MCS51
    byteorder = Byteorder.BIG

    address_spaces = MCS51_ADDRESS_SPACES
    userops = MCS51UserOp

    def update_derived_state(self, emulator) -> None:
        # Ghidra's 8051 language never computes the parity flag.
        psw = emulator.read_register("psw")
        new_psw = mcs51_psw_with_parity(psw, emulator.read_register("acc"))
        if new_psw != psw:
            emulator.write_register("psw", new_psw)

    _registers = {
        "pc": "PC",
        "sp": "SP",
        "acc": "ACC",
        "a": "ACC",
        "b": "B",
        "psw": "PSW",
        "dptr": "DPTR",
        "dph": "DPH",
        "dpl": "DPL",
        "r0": "R0",
        "r1": "R1",
        "r2": "R2",
        "r3": "R3",
        "r4": "R4",
        "r5": "R5",
        "r6": "R6",
        "r7": "R7",
    }
