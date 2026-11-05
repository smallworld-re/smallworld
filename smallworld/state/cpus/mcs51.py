from ... import platforms
from .. import state
from . import cpu


class MCS51(cpu.CPU):
    """CPU state for the Intel MCS-51 (8051).

    R0-R7 are the working registers of the current bank.  On real hardware
    they live in internal RAM at 0x00-0x1F, in the bank PSW's RS bits select.
    When internal RAM 0x00-0x1F is mapped, the emulators keep these registers
    and that bank in step, and these values are written into the selected
    bank when emulation starts; otherwise they are registers of their own.

    ``xpage_sfr`` is not a register of the hardware but a property of the
    device: the address of the SFR that supplies the high byte of MOVX @Ri's
    address.  The emulators set it to P2's (0xA0), as on Intel's 8051; set it
    to EMI0CN's to emulate a Silicon Labs CIP-51 device.
    """

    platform = platforms.Platform(platforms.Architecture.MCS51, platforms.Byteorder.BIG)

    def __init__(self):
        super().__init__()
        self.pc = state.Register("pc", 2)
        self.add(self.pc)
        # SP is an 8-bit index into internal RAM.
        self.sp = state.Register("sp", 1)
        self.add(self.sp)
        self.acc = state.Register("acc", 1)
        self.add(self.acc)
        self.a = state.RegisterAlias("a", self.acc, 1, 0)
        self.add(self.a)
        self.b = state.Register("b", 1)
        self.add(self.b)
        self.psw = state.Register("psw", 1)
        self.add(self.psw)
        self.dptr = state.Register("dptr", 2)
        self.add(self.dptr)
        self.dph = state.RegisterAlias("dph", self.dptr, 1, 1)
        self.add(self.dph)
        self.dpl = state.RegisterAlias("dpl", self.dptr, 1, 0)
        self.add(self.dpl)
        self.xpage_sfr = state.Register("xpage_sfr", 1)
        self.add(self.xpage_sfr)
        for i in range(0, 8):
            reg = state.Register(f"r{i}", 1)
            setattr(self, f"r{i}", reg)
            self.add(reg)
