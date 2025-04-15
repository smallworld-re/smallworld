class RegisterState:
    def __init__(self, registers: dict, pc: int, sp: int, status: int, arch: str):
        self.arch = arch
        self.pc = pc
        self.sp = sp
        self.status = status

        # The rest of the registers
        self._registers = registers

    def __getattr__(self, name: str):
        if name in self._registers:
            return self._registers[name]

        raise AttributeError(f"No register named '{name}' in this core dump.")

    def __setattr__(self, name: str, value):
        super().__setattr__(name, value)
