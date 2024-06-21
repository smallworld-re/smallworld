import archinfo

from .machdef import AngrMachineDef


class ARMMachineDef(AngrMachineDef):
    arch = "arm"
    pc_reg = "pc"

    def __init__(self):
        self._registers = {
            # *** General-purpose registers ***
            "r0": "r0",
            "r1": "r1",
            "r2": "r2",
            "r3": "r3",
            "r4": "r4",
            "r5": "r5",
            "r6": "r6",
            "r7": "r7",
            "r8": "r8",
            # r9 doubles as the Static base pointer
            "r9": "r9",
            "sb": "sb",
            # r10 doubles as the Stack Limit pointer
            "r10": "r10",
            "sl": "sl",
            # r11 doubles as the Frame Pointer, if desired.
            "r11": "r11",
            "fp": "fp",
            # r12 doubles as the Intra-call scratch register
            "r12": "r12",
            "ip": "ip",
            "sp": "sp",
            "lr": "lr",
            "pc": "pc",
        }


class ARMMachineMixinM:
    """Mixin class for M-series CPUs.

    The main difference between M and R/A
    is the available system status registers.
    """

    angr_arch = archinfo.arch_arm.ArchARMCortexM()

    def __init__(self):
        super().__init__()
        self._registers.update(
            {
                # *** Special Registers ***
                # Program Status Register
                # NOTE: PSR can be accessed through several masked aliases.
                # These are read-only, so I'm not including them.
                # - apsr: Just the condition flags
                # - ipsr: Just exception information
                # - epsr: Just execution state info
                # - iapsr: apsr | ipsr
                # - eapsr: apsr | epsr
                # - iepsr: ipsr | epsr
                # - xpsr: apsr | ipsr | epsr
                "psr": "cpsr",
                # Exception Mask Register
                "primask": "primask",
                # Base Priority Mask Register
                "basepri": "basepri",
                # Fault Mask Register
                "faultmask": "faultmask",
                # Control register; includes a lot of flags.
                "control": "control",
                # *** Stack Pointer Bank ***
                # sp is actually an alias to one of these two.
                # Exactly which one depends on a bit in control.
                # Emulators that care should be careful when loading state.
                # Main Stack Pointer
                "msp": "msp",
                # Process Stack Pointer
                "psp": "psp",
            }
        )


class ARMMachineMixinFP:
    """Mixin for ARM CPUs with FP extensions

    This is one kind of floating-point extension
    which offers 64-bit scalar operations.
    """

    def __init__(self):
        super().__init__()
        self._registers.update(
            {
                # *** Floating point control registers ***
                # Floating-point Status and Control Register
                "fpscr": "fpscr",
                # Floating-point Exception Control Register
                "fpexc": "fpexc",
                # Floating-point System ID Register
                "fpsid": "fpsid",
                # Media and VFP Feature Register 0
                "mvfr0": "mvfr0",
                # Media and VFP Feature Register 1
                "mvfr1": "mvfr1",
                # *** Floating point registers ***
                "d0": "d0",
                "s0": "s0",
                "s1": "s1",
                "d1": "d1",
                "s2": "s2",
                "s3": "s3",
                "d2": "d2",
                "s4": "s4",
                "s5": "s5",
                "d3": "d3",
                "s6": "s6",
                "s7": "s7",
                "d4": "d4",
                "s8": "s8",
                "s9": "s9",
                "d5": "d5",
                "s10": "s10",
                "s11": "s11",
                "d6": "d6",
                "s12": "s12",
                "s13": "s13",
                "d7": "d7",
                "s14": "s14",
                "s15": "s15",
                "d8": "d8",
                "s16": "s16",
                "s17": "s17",
                "d9": "d9",
                "s18": "s18",
                "s19": "s19",
                "d10": "d10",
                "s20": "s20",
                "s21": "s21",
                "d11": "d11",
                "s22": "s22",
                "s23": "s23",
                "d12": "d12",
                "s24": "s24",
                "s25": "s25",
                "d13": "d13",
                "s26": "s26",
                "s27": "s27",
                "d14": "d14",
                "s28": "s28",
                "s29": "s29",
                "d15": "d15",
                "s30": "s30",
                "s31": "s31",
            }
        )


class ARMv5TMachineDef(ARMMachineMixinM, ARMMachineDef):
    arch = "arm"
    mode = "v5t"
    byteorder = "little"


class ARMv6MMachineDef(ARMMachineMixinFP, ARMMachineMixinM, ARMMachineDef):
    arch = "arm"
    mode = "v6m"
    byteorder = "little"


class ARMv7MMachineDef(ARMMachineMixinFP, ARMMachineMixinM, ARMMachineDef):
    arch = "arm"
    mode = "v7m"
    byteorder = "little"


# angr does not have good enough R- or A- series support,
# or any support for NEON that I can see.
