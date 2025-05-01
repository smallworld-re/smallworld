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
        if name.startswith("_") or name in ("arch", "pc", "sp", "status"):
            super().__setattr__(name, value)
        else:
            if hasattr(self, "_registers") and (name in self._registers):
                self._registers[name] = value
            else:
                super().__setattr__(name, value)

    def apply_to_cpu(self, cpu):
        """
        Set the CPU registers from this RegisterState object.
        """
        cpu.pc.set(self.pc)
        cpu.sp.set(self.sp)

        for reg_name, reg_val in self._registers.items():
            reg_name_lower = reg_name.lower()
            if hasattr(cpu, reg_name_lower):
                getattr(cpu, reg_name_lower).set(reg_val)
