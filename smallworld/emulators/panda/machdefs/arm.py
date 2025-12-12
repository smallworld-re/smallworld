from ....platforms import Architecture, Byteorder
from .machdef import PandaMachineDef


class ARMMachineDef(PandaMachineDef):
    panda_arch = "arm"

    # I'm going to define all the ones we are making possible as of now
    # I need to submit a PR to change to X86 32 bit and to includ eflags
    def __init__(self):
        self._registers = {
            "r0",
            "r1",
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
            "sp",
            "lr",
            "pc",
        }

        self._registers = {i: i for i in self._registers}
        self._registers = self._registers | {
            "sb": "r9",
            "sl": "r10",
            "fp": "r11",
            "ip": "r12",
        }


class ARMMachineMixinM:
    """Mixin for ARM M-series machine models"""

    def __init__(self):
        super().__init__()
        self._registers_m = {
            # NOTE: None of the expected privileged registers exist
            "psr",
            "primask",
            "basepri",
            "faultmask",
            "control",
            "msp",
            "psp",
        }
        self._registers = self._registers | {i: None for i in self._registers_m}


class ARMMachineMixinFP:
    def __init__(self):
        super().__init__()
        self._registers_fp = {
            "fpscr",
            "fpexc",
            "fpsid",
            "mvfr0",
            "mvfr1",
            "d0",
            "s0",
            "s1",
            "d1",
            "s2",
            "s3",
            "d2",
            "s4",
            "s5",
            "d3",
            "s6",
            "s7",
            "d4",
            "s8",
            "s9",
            "d5",
            "s10",
            "s11",
            "d6",
            "s12",
            "s13",
            "d7",
            "s14",
            "s15",
            "d8",
            "s16",
            "s17",
            "d9",
            "s18",
            "s19",
            "d10",
            "s20",
            "s21",
            "d11",
            "s22",
            "s23",
            "d12",
            "s24",
            "s25",
            "d13",
            "s26",
            "s27",
            "d14",
            "s28",
            "s29",
            "d15",
            "s30",
            "s31",
        }
        self._registers = self._registers | {i: None for i in self._registers_fp}


class ARMMachineMixinA:
    """Mixin for ARM A-series machine models"""

    def __init__(self):
        super().__init__()
        # TODO: QEMU doesn't quite support what I expect.
        # I expected to see cpsr and spsr.
        # I either got the CPU model wrong, or something else is weird.
        # (I strongly suspect Panda exposes the bitmasked aliases of cpsr)
        self._registers_a = {
            "cpsr": None,
            "spsr": None,
            "sp_usr": None,
            "lr_usr": None,
            "r8_usr": None,
            "r9_usr": None,
            "r10_usr": None,
            "r11_usr": None,
            "r12_usr": None,
            "sp_hyp": None,
            "spsr_hyp": None,
            "elr_hyp": None,
            "sp_svc": None,
            "lr_svc": None,
            "spsr_svc": None,
            "sp_abt": None,
            "lr_abt": None,
            "spsr_abt": None,
            "sp_und": None,
            "lr_und": None,
            "spsr_und": None,
            "sp_mon": None,
            "lr_mon": None,
            "spsr_mon": None,
            "sp_irq": None,
            "lr_irq": None,
            "spsr_irq": None,
            "sp_fiq": None,
            "lr_fiq": None,
            "spsr_fiq": None,
            "r8_fiq": None,
            "r9_fiq": None,
            "r10_fiq": None,
            "r11_fiq": None,
            "r12_fiq": None,
        }
        self._registers = self._registers | {k: v for k, v in self._registers_a.items()}


class ARMMachineMixinVFP:
    def __init__(self):
        super().__init__()
        self._registers_vfp = {
            # *** Floating-point Control Registers ***
            # Floating-point Status and Control Register
            "fpscr",
            # Floating-point Exception Control Register
            "fpexc",
            # Floating-point System ID Register
            "fpsid",
            # Media and VFP Feature Register 0
            "mvfr0",
            # Media and VFP Feature Register 1
            "mvfr1",
            # *** Floating-point Registers ****
            "q0",
            "d0",
            "s0",
            "s1",
            "d1",
            "s2",
            "s3",
            "q1",
            "d2",
            "s4",
            "s5",
            "d3",
            "s6",
            "s7",
            "q2",
            "d4",
            "s8",
            "s9",
            "d5",
            "s10",
            "s11",
            "q3",
            "d6",
            "s12",
            "s13",
            "d7",
            "s14",
            "s15",
            "q4",
            "d8",
            "s16",
            "s17",
            "d9",
            "s18",
            "s19",
            "q5",
            "d10",
            "s20",
            "s21",
            "d11",
            "s22",
            "s23",
            "q6",
            "d12",
            "s24",
            "s25",
            "d13",
            "s26",
            "s27",
            "q7",
            "d14",
            "s28",
            "s29",
            "d15",
            "s30",
            "s31",
            "q8",
            "d16",
            "d17",
            "q9",
            "d18",
            "d19",
            "q10",
            "d20",
            "d21",
            "q11",
            "d22",
            "d23",
            "q12",
            "d24",
            "d25",
            "q13",
            "d26",
            "d27",
            "q14",
            "d28",
            "d29",
            "q15",
            "d30",
            "d31",
        }
        self._registers = self._registers | {i: None for i in self._registers_vfp}


class ARMv5TMachineDef(ARMMachineMixinM, ARMMachineDef):
    arch = Architecture.ARM_V5T
    byteorder = Byteorder.LITTLE
    cpu = "arm926"


# TODO: Something's very weird with Panda's Arm 7 models.
# cortex-a9 should be an A-series, but it looks more like an M-series.
# cortex-m4 looks like an M-series, but aborts; I suspect we're missing configuration.
class ARMv7AMachineDef(ARMMachineMixinVFP, ARMMachineMixinA, ARMMachineDef):
    arch = Architecture.ARM_V7A
    byteorder = Byteorder.LITTLE
    cpu = "cortex-a9"


class ARMv7MMachineDef(ARMMachineMixinFP, ARMMachineMixinM, ARMMachineDef):
    arch = Architecture.ARM_V7M
    byteorder = Byteorder.LITTLE
    cpu = "cortex-m4"
