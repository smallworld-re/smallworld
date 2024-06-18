from ..state import CPU, Register


class PowerPCCPUState(CPU):
    """CPU state for PowerPC 32.

    Unicorn and Sleigh disagree on what they call many registers.
    """

    arch = "powerpc"
    mode = "ppc32"
    byteorder = "big"

    def __init__(self):
        self.MSR = Register("MSR", width=4)
        self.pc = Register("pc", width=4)
        self.cr0 = Register("cr0", width=1)
        self.cr1 = Register("cr1", width=1)
        self.cr2 = Register("cr2", width=1)
        self.cr3 = Register("cr3", width=1)
        self.cr4 = Register("cr4", width=1)
        self.cr5 = Register("cr5", width=1)
        self.cr6 = Register("cr6", width=1)
        self.cr7 = Register("cr7", width=1)
        self.XER = Register("XER", width=4)
        self.LR = Register("LR", width=4)
        self.CTR = Register("CTR", width=4)
