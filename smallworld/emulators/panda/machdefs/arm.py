import re

from .... import exceptions
from ....platforms import Architecture, Byteorder
from .machdef import PandaMachineDef

# QEMU's ARM prefetch (instruction) abort exception index (target/arm cpu.h
# EXCP_PREFETCH_ABORT). PANDA raises it when the CPU fetches an instruction
# from unmapped memory, so it maps to a fetch-unmapped failure.
_ARM_EXCP_PREFETCH_ABORT = 3

# FPEXC's index in CPUARMState's vfp.xregs (target/arm cpu.h ARM_VFP_FPEXC).
_ARM_VFP_FPEXC = 8

# CPACR's full-access grants for CP10 and CP11, the FPU's coprocessors.
_CPACR_CP10_CP11 = 0xF << 20

_VFP_DATA_REGISTER = re.compile(r"([sdq])(\d+)$")

# The FP registers PANDA reaches through the CPU state. The ID registers
# (fpsid, mvfrN) stay unsupported: QEMU reads the CPU's features from a
# separate copy, so writing them would change nothing.
_FP_STATE_REGISTERS = frozenset(
    {"fpscr", "fpexc"} | {f"s{i}" for i in range(32)} | {f"d{i}" for i in range(16)}
)
_VFP_STATE_REGISTERS = (
    _FP_STATE_REGISTERS
    | {f"d{i}" for i in range(16, 32)}
    | {f"q{i}" for i in range(16)}
)


class ARMMachineDef(PandaMachineDef):
    panda_arch = "arm"

    def handle_interrupt(self, intno: int, pc: int) -> None:
        if intno == _ARM_EXCP_PREFETCH_ABORT:
            raise exceptions.EmulationFetchUnmappedFailure(
                f"Fetched unmapped memory at {hex(pc)}", pc, address=pc
            )
        super().handle_interrupt(intno, pc)

    # PANDA's register accessors reach only the core registers, so the FP
    # registers, and cpacr, which gates access to them, live in the CPU state.
    # QEMU caches whether the FPU is enabled, and FPSCR's vector length and
    # stride, in the CPU's hflags, so writing cpacr, fpexc or fpscr rebuilds
    # them.

    def read_state_register(self, name: str, panda_obj, panda_cpu) -> int:
        env = panda_obj.cpu_env(panda_cpu)
        if name == "cpacr":
            return int(env.cp15.cpacr_el1) & 0xFFFFFFFF
        if name == "fpexc":
            return int(env.vfp.xregs[_ARM_VFP_FPEXC])
        if name == "fpscr":
            return int(panda_obj.libpanda.vfp_get_fpscr(env))
        kind, n = self._vfp_data_register(name)
        if kind == "q":
            lanes = env.vfp.zregs[n].d
            return int(lanes[0]) | int(lanes[1]) << 64
        if kind == "d":
            return int(env.vfp.zregs[n >> 1].d[n & 1])
        d = int(env.vfp.zregs[n >> 2].d[(n >> 1) & 1])
        return (d >> (32 * (n & 1))) & 0xFFFFFFFF

    def write_state_register(self, name: str, value: int, panda_obj, panda_cpu) -> None:
        env = panda_obj.cpu_env(panda_cpu)
        if name in ("cpacr", "fpexc", "fpscr"):
            value &= 0xFFFFFFFF
            if name == "cpacr":
                env.cp15.cpacr_el1 = value
            elif name == "fpexc":
                env.vfp.xregs[_ARM_VFP_FPEXC] = value
            else:
                panda_obj.libpanda.vfp_set_fpscr(env, value)
            panda_obj.libpanda.arm_rebuild_hflags(env)
            return
        kind, n = self._vfp_data_register(name)
        if kind == "q":
            value &= (1 << 128) - 1
            env.vfp.zregs[n].d[0] = value & 0xFFFFFFFFFFFFFFFF
            env.vfp.zregs[n].d[1] = value >> 64
        elif kind == "d":
            env.vfp.zregs[n >> 1].d[n & 1] = value & 0xFFFFFFFFFFFFFFFF
        else:
            lanes = env.vfp.zregs[n >> 2].d
            shift = 32 * (n & 1)
            d = int(lanes[(n >> 1) & 1]) & ~(0xFFFFFFFF << shift)
            lanes[(n >> 1) & 1] = d | (value & 0xFFFFFFFF) << shift

    def _vfp_data_register(self, name: str):
        match = _VFP_DATA_REGISTER.match(name)
        if match is None:
            raise exceptions.UnsupportedRegisterError(
                f"Register {name} not recognized by Panda for {self.arch}:{self.byteorder}"
            )
        return match.group(1), int(match.group(2))

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
            "r13": "sp",
            "r14": "lr",
            "r15": "pc",
        }


class ARMMachineMixinM:
    """Mixin for ARM M-series machine models"""

    def __init__(self):
        super().__init__()
        self._registers_m = {
            # NOTE: None of the expected privileged registers exist
            "psr",
            "primask",
            "control",
            "msp",
            "psp",
        }
        self._registers = self._registers | {i: None for i in self._registers_m}

    # M-profile is Thumb-only, but QEMU keeps the Thumb state apart from the
    # pc, in EPSR.T, and resets it from the reset vector, which these boards
    # leave empty. So a pc write clears the Thumb bit from the pc, where QEMU
    # would fault on it, and sets EPSR.T, without which the next instruction
    # raises an invalid-state UsageFault.

    def pc_written(self, panda_obj, panda_cpu) -> None:
        env = panda_obj.cpu_env(panda_cpu)
        env.regs[15] &= ~1
        env.thumb = 1

    # The M-profile boards have RAM where SmallWorld may not map any.
    checks_fetches = True


class ARMMachineMixinMFP:
    """Mixin for M-profile CPUs with the single-precision FPv4-SP-D16 FPU"""

    def __init__(self):
        super().__init__()
        registers = (
            {"fpscr"} | {f"s{i}" for i in range(32)} | {f"d{i}" for i in range(16)}
        )
        self._registers = self._registers | {i: None for i in registers}
        self._state_registers = self._state_registers | registers

    # The FPU resets disabled. M-profile has no cpacr register to enable it
    # through, so the machine enables it from the start, in both security
    # states' copies of CPACR, as Unicorn does.

    def setup_cpu(self, panda_obj, panda_cpu) -> None:
        env = panda_obj.cpu_env(panda_cpu)
        for secure in range(2):
            env.v7m.cpacr[secure] |= _CPACR_CP10_CP11
        panda_obj.libpanda.arm_rebuild_hflags(env)


class ARMMachineMixinMMainline(ARMMachineMixinM):
    """Mixin for ARMv7-M machine models, which add priority masks to ARMv6-M"""

    def __init__(self):
        super().__init__()
        self._registers = self._registers | {"basepri": None, "faultmask": None}


class ARMMachineMixinV5SystemControl:
    """Mixin for ARMv5 CPUs with a cp15 system control coprocessor"""

    def __init__(self):
        super().__init__()
        self._registers = self._registers | {
            "midr": None,
            "ctr": None,
            "sctlr": None,
            "ttbr": None,
            "dacr": None,
            "fsr": None,
            "far": None,
            "fcseidr": None,
        }


class ARMMachineMixinV6SystemControl:
    """Mixin for ARMv6 CPUs with a cp15 system control coprocessor"""

    def __init__(self):
        super().__init__()
        self._registers = self._registers | {
            "midr": None,
            "ctr": None,
            "sctlr": None,
            "actlr": None,
            "cpacr": None,
            "ttbr0": None,
            "ttbr1": None,
            "ttbcr": None,
            "dacr": None,
            "dfsr": None,
            "ifsr": None,
            "dfar": None,
            "wfar": None,
            "ifar": None,
            "par": None,
            "prrr": None,
            "nmrr": None,
            "vbar": None,
            "fcseidr": None,
            "contextidr": None,
            "tpidrurw": None,
            "tpidruro": None,
            "tpidrprw": None,
        }
        # cpacr gates access to the FPU, so it lives in the CPU state.
        self._state_registers = self._state_registers | {"cpacr"}


class ARMMachineMixinV7SystemControl:
    """Mixin for the cp15 registers common to ARMv7-A and ARMv7-R"""

    def __init__(self):
        super().__init__()
        self._registers = self._registers | {
            "midr": None,
            "ctr": None,
            "mpidr": None,
            "sctlr": None,
            "actlr": None,
            "cpacr": None,
            "csselr": None,
            "dfsr": None,
            "ifsr": None,
            "dfar": None,
            "ifar": None,
            "contextidr": None,
            "tpidrurw": None,
            "tpidruro": None,
            "tpidrprw": None,
        }
        # cpacr gates access to the FPU, so it lives in the CPU state.
        self._state_registers = self._state_registers | {"cpacr"}


class ARMMachineMixinPMSA:
    """Mixin for ARMv7 CPUs with an MPU (the R-series)"""

    def __init__(self):
        super().__init__()
        self._registers = self._registers | {
            "rgnr": None,
            "drbar": None,
            "drsr": None,
            "dracr": None,
        }


class ARMMachineMixinVMSA:
    """Mixin for ARMv7 CPUs with an MMU and the Large Physical Address Extension"""

    def __init__(self):
        super().__init__()
        self._registers = self._registers | {
            "ttbr0": None,
            "ttbr1": None,
            "ttbcr": None,
            "dacr": None,
            "par": None,
            "prrr": None,
            "nmrr": None,
            "vbar": None,
        }


class ARMMachineMixinGenericTimer:
    """Mixin for ARMv7 CPUs with the Generic Timer Extension"""

    def __init__(self):
        super().__init__()
        self._registers = self._registers | {
            "cntfrq": None,
            "cntkctl": None,
            "cntpct": None,
            "cntvct": None,
            "cntp_ctl": None,
            "cntp_cval": None,
            "cntv_ctl": None,
            "cntv_cval": None,
        }


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
        self._state_registers = self._state_registers | _FP_STATE_REGISTERS


class ARMMachineMixinBanked:
    """Mixin for ARM machine models with the classic banked-register model"""

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
            "sp_svc": None,
            "lr_svc": None,
            "spsr_svc": None,
            "sp_abt": None,
            "lr_abt": None,
            "spsr_abt": None,
            "sp_und": None,
            "lr_und": None,
            "spsr_und": None,
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


class ARMMachineMixinSecurity:
    """Mixin for CPUs with the Security Extensions (TrustZone)."""

    def __init__(self):
        super().__init__()
        self._registers = self._registers | {
            "sp_mon": None,
            "lr_mon": None,
            "spsr_mon": None,
            "scr": None,
            "sder": None,
            "nsacr": None,
            "mvbar": None,
        }


class ARMMachineMixinVirtualization:
    """Mixin for CPUs with the Virtualization Extensions."""

    def __init__(self):
        super().__init__()
        self._registers = self._registers | {
            "sp_hyp": None,
            "spsr_hyp": None,
            "elr_hyp": None,
            "hcr": None,
            "hcptr": None,
            "hstr": None,
            "hdcr": None,
            "hsctlr": None,
            "hvbar": None,
            "httbr": None,
            "htcr": None,
            "vttbr": None,
            "vtcr": None,
            "hsr": None,
            "hdfar": None,
            "hifar": None,
            "hpfar": None,
            "htpidr": None,
            "hmair0": None,
            "hmair1": None,
            "vpidr": None,
            "vmpidr": None,
            "cntvoff": None,
            "cnthctl": None,
            "cnthp_ctl": None,
            "cnthp_cval": None,
        }


class ARMMachineMixinVFPv2(ARMMachineMixinFP):
    """Mixin for little-endian ARM CPUs with VFPv2"""

    def __init__(self):
        super().__init__()
        self._registers = self._registers | {
            "fpinst": None,
            "fpinst2": None,
        }


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
        self._state_registers = self._state_registers | _VFP_STATE_REGISTERS


class ARMMachineMixinVFPv8(ARMMachineMixinVFP):
    """Mixin for little-endian ARMv8 AArch32 CPUs with FP and Advanced SIMD"""

    def __init__(self):
        super().__init__()
        self._registers = self._registers | {
            "mvfr2": None,
        }


class ARMMachineMixinPMSAv8:
    """Mixin for ARMv8-R CPUs with the PMSAv8-32 MPU"""

    def __init__(self):
        super().__init__()
        self._registers = self._registers | {
            "prselr": None,
            "prbar": None,
            "prlar": None,
            "mair0": None,
            "mair1": None,
            "vbar": None,
        }


class ARMMachineMixinV8RHypervisor:
    """Mixin for ARMv8-R CPUs' Hypervisor mode (EL2)"""

    def __init__(self):
        super().__init__()
        self._registers = self._registers | {
            "sp_hyp": None,
            "spsr_hyp": None,
            "elr_hyp": None,
            "hcr": None,
            "hcptr": None,
            "hstr": None,
            "hdcr": None,
            "hsctlr": None,
            "hvbar": None,
            "hsr": None,
            "hdfar": None,
            "hifar": None,
            "htpidr": None,
            "hmair0": None,
            "hmair1": None,
            "vpidr": None,
            "vmpidr": None,
            "hprselr": None,
            "hprbar": None,
            "hprlar": None,
            "cntvoff": None,
            "cnthctl": None,
            "cnthp_ctl": None,
            "cnthp_cval": None,
        }


class ARMMachineMixinV8MMainline(ARMMachineMixinMMainline):
    """Abstract class for ARMv8-M Mainline CPUs."""

    def __init__(self):
        super().__init__()
        self._registers = self._registers | {
            "msplim": None,
            "psplim": None,
        }


class ARMv4MachineDef(
    ARMMachineMixinV5SystemControl, ARMMachineMixinBanked, ARMMachineDef
):
    arch = Architecture.ARM_V4
    byteorder = Byteorder.LITTLE
    # The StrongARM SA-1110: ARMv4, no Thumb.
    cpu = "sa1110"


class ARMv4TMachineDef(
    ARMMachineMixinV5SystemControl, ARMMachineMixinBanked, ARMMachineDef
):
    arch = Architecture.ARM_V4T
    byteorder = Byteorder.LITTLE
    # The TI925T: an ARM9 core implementing ARMv4T.
    cpu = "ti925t"


class ARMv5TMachineDef(
    ARMMachineMixinV5SystemControl, ARMMachineMixinBanked, ARMMachineDef
):
    arch = Architecture.ARM_V5T
    byteorder = Byteorder.LITTLE
    cpu = "arm926"


class ARMv6KMachineDef(
    ARMMachineMixinVFPv2,
    ARMMachineMixinSecurity,
    ARMMachineMixinV6SystemControl,
    ARMMachineMixinBanked,
    ARMMachineDef,
):
    arch = Architecture.ARM_V6K
    byteorder = Byteorder.LITTLE
    cpu = "arm1176"


# TODO: I have no idea which board to use.
# I'm hoping that v6m code is compatible with a v7m-ish machine.
class ARMv6MMachineDef(ARMMachineMixinM, ARMMachineDef):
    arch = Architecture.ARM_V6M
    byteorder = Byteorder.LITTLE
    cpu = "cortex-a9"


# TODO: Something's very weird with Panda's Arm 7 models.
# cortex-a9 should be an A-series, but it looks more like an M-series.
# cortex-m4 looks like an M-series, but aborts; I suspect we're missing configuration.
class ARMv7AMachineDef(
    ARMMachineMixinVFP,
    ARMMachineMixinVirtualization,
    ARMMachineMixinSecurity,
    ARMMachineMixinGenericTimer,
    ARMMachineMixinVMSA,
    ARMMachineMixinV7SystemControl,
    ARMMachineMixinBanked,
    ARMMachineDef,
):
    arch = Architecture.ARM_V7A
    byteorder = Byteorder.LITTLE
    cpu = "cortex-a9"


# TODO: This is not the right CPU, but might be close enough
# PANDA runs M-profile only on its boards for M-profile CPUs; its
# configurable machine rejects them. Each board brings its own memory map:
# board RAM would let accesses to addresses SmallWorld didn't map succeed
# rather than fault, so PANDA checks fetches as well as reads and writes
# against SmallWorld's map. Board flash and devices shadow memory SmallWorld
# maps over them. The mps2 boards need exactly 16 MiB of RAM.


class ARMv7MMachineDef(ARMMachineMixinMMainline, ARMMachineDef):
    arch = Architecture.ARM_V7M
    byteorder = Byteorder.LITTLE
    machine = "mps2-an385"
    cpu = "cortex-m3"
    mem = "16M"


class ARMv7EMMachineDef(ARMMachineMixinMFP, ARMMachineMixinMMainline, ARMMachineDef):
    arch = Architecture.ARM_V7EM
    byteorder = Byteorder.LITTLE
    machine = "mps2-an386"
    cpu = "cortex-m4"
    mem = "16M"


class ARMv8MMachineDef(ARMMachineMixinV8MMainline, ARMMachineDef):
    arch = Architecture.ARM_V8M
    byteorder = Byteorder.LITTLE
    machine = "mps2-an505"
    cpu = "cortex-m33"
    mem = "16M"


class ARMv8AMachineDef(
    ARMMachineMixinVFPv8,
    ARMMachineMixinVirtualization,
    ARMMachineMixinSecurity,
    ARMMachineMixinGenericTimer,
    ARMMachineMixinVMSA,
    ARMMachineMixinV7SystemControl,
    ARMMachineMixinBanked,
    ARMMachineDef,
):
    arch = Architecture.ARM_V8A
    byteorder = Byteorder.LITTLE
    # PANDA's 32-bit ARM build has no ARMv8-A core; "max" is a superset.
    cpu = "max"


class ARMv8RMachineDef(
    ARMMachineMixinVFPv8,
    ARMMachineMixinV8RHypervisor,
    ARMMachineMixinGenericTimer,
    ARMMachineMixinPMSAv8,
    ARMMachineMixinV7SystemControl,
    ARMMachineMixinBanked,
    ARMMachineDef,
):
    arch = Architecture.ARM_V8R
    byteorder = Byteorder.LITTLE
    cpu = "cortex-r52"


class ARMv7RMachineDef(
    ARMMachineMixinFP,
    ARMMachineMixinPMSA,
    ARMMachineMixinV7SystemControl,
    ARMMachineMixinBanked,
    ARMMachineDef,
):
    arch = Architecture.ARM_V7R
    byteorder = Byteorder.LITTLE
    # The R5F, unlike the R5, has the 16-register VFP this platform models.
    cpu = "cortex-r5f"


# Big-endian ARMv6 and later are BE8: instructions stay little-endian, and
# CPSR.E makes data accesses big-endian. PANDA runs them on its little-endian
# cores with CPSR.E set, and with SCTLR.EE set too, so that exception entry,
# which loads CPSR.E from SCTLR.EE, keeps them big-endian. sctlr_el[1] to [3]
# hold the non-secure, Hyp and secure SCTLRs. QEMU caches the data
# endianness in the CPU's hflags, so setting them rebuilds those.

_CPSR_E = 1 << 9
_SCTLR_EE = 1 << 25


class ARMMachineMixinBE8:
    byteorder = Byteorder.BIG

    def setup_cpu(self, panda_obj, panda_cpu) -> None:
        env = panda_obj.cpu_env(panda_cpu)
        for el in range(1, 4):
            env.cp15.sctlr_el[el] |= _SCTLR_EE
        env.uncached_cpsr |= _CPSR_E
        panda_obj.libpanda.arm_rebuild_hflags(env)


class ARMv6KBEMachineDef(ARMMachineMixinBE8, ARMv6KMachineDef):
    pass


class ARMv7ABEMachineDef(ARMMachineMixinBE8, ARMv7AMachineDef):
    pass


class ARMv7RBEMachineDef(ARMMachineMixinBE8, ARMv7RMachineDef):
    pass


class ARMv8ABEMachineDef(ARMMachineMixinBE8, ARMv8AMachineDef):
    pass


class ARMv8RBEMachineDef(ARMMachineMixinBE8, ARMv8RMachineDef):
    pass
