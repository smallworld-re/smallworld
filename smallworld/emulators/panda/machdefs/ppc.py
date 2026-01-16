from ....platforms import Architecture, Byteorder
from .machdef import PandaMachineDef


class PowerPCMachineDef(PandaMachineDef):
    byteorder = Byteorder.BIG

    panda_arch = "ppc"

    # I'm going to define all the ones we are making possible as of now
    # I need to submit a PR to change to X86 32 bit and to includ eflags
    _registers_identity = {
        "r0",
        "r2",
        "r3",
        "r4",
        "r5",
        "r6",
        "r7",
        "r8",
        "r9",
        "r10",
        "r11",
        "r12",
        "r13",
        "r14",
        "r15",
        "r16",
        "r17",
        "r18",
        "r19",
        "r20",
        "r21",
        "r22",
        "r23",
        "r24",
        "r25",
        "r26",
        "r27",
        "r28",
        "r29",
        "r30",
        "r31",
        "cr0",
        "cr1",
        "cr2",
        "cr3",
        "cr4",
        "cr5",
        "cr6",
        "cr7",
        "pc",
        "sp",
        "lr",
        "ctr",
    }
    _registers_mapping = {
        "r1": "sp",
        "bp": "r31",
    }
    _registers_unsupported = {
        "f0",
        "f1",
        "f2",
        "f3",
        "f4",
        "f5",
        "f6",
        "f7",
        "f8",
        "f9",
        "f10",
        "f11",
        "f12",
        "f13",
        "f14",
        "f15",
        "f16",
        "f17",
        "f18",
        "f19",
        "f20",
        "f21",
        "f22",
        "f23",
        "f24",
        "f25",
        "f26",
        "f27",
        "f28",
        "f29",
        "f30",
        "f31",
        "xer",
        "fpscr",
    }
    _registers = {i: j for i, j in _registers_mapping.items()}
    _registers = _registers | {i: i for i in _registers_identity}
    _registers = _registers | {i: None for i in _registers_unsupported}


class PowerPC32MachineDef(PowerPCMachineDef):
    arch = Architecture.POWERPC32
    cpu = "ppc32"

    def _panda_get_spr_regs(self, panda_obj, panda_cpu):
        # HACKHACK: export something in pypanda to do this instead of duplicating.
        # We'll also be paranoid in reading this in case the upstream patch hasn't landed.
        if getattr(panda_obj.arch, 'registers_spr', None) is None:
            # print(f'obtaining PANDA spr regs')
            env = panda_obj.cpu_env(panda_cpu)
            panda_obj.arch.registers_spr = {}
            for idx, spr_cb in enumerate(env.spr_cb):
                if spr_cb.name:
                    pystr = panda_obj.arch.panda.ffi.string(spr_cb.name).decode('utf-8')
                    panda_obj.arch.registers_spr['SPR_' + pystr] = idx

    def panda_reg(self, name: str, panda_obj, panda_cpu) -> str:
        if name in self._registers:
            res = self._registers[name]
            if res is None:
                raise exceptions.UnsupportedRegisterError(
                    f"Register {name} not recognized by Panda for {self.arch}:{self.byteorder}"
                )
            return res
        elif name.startswith('SPR_'):
            self._panda_get_spr_regs(panda_obj, panda_cpu)
            if name.upper() in panda_obj.arch.registers_spr.keys():
                return name.upper()
            raise exceptions.UnsupportedRegisterError(
                f"SPR {name} not recognized by Panda for {self.arch}:{self.byteorder}"
            )
        else:
            raise ValueError(
                f"Unknown register for {self.arch}:{self.byteorder}: {name}"
            )

    def check_panda_reg(self, name: str, panda_obj, panda_cpu) -> bool:
        """Convert a register name to panda cpu field, index, mask

        This must cover all names defined in the CPU state model
        for this arch/mode/byteorder, or return 0,
        which always indicates an invalid register
        """
        if name in self._registers and self._registers[name] is not None:
            return True
        elif name.startswith('SPR_'):
            self._panda_get_spr_regs(panda_obj, panda_cpu)
            return name.upper() in panda_obj.arch.registers_spr.keys()
        else:
            return False
