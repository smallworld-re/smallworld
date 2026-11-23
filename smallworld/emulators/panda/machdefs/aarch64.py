from .... import exceptions
from ....platforms import Architecture, Byteorder
from .machdef import PandaMachineDef

# QEMU shares the AArch32/AArch64 exception indices (target/arm cpu.h); a
# prefetch (instruction) abort is EXCP_PREFETCH_ABORT = 3, raised when the CPU
# fetches an instruction from unmapped memory.
_ARM_EXCP_PREFETCH_ABORT = 3

# The views of each SIMD and FP register, by width in bits.
_VECTOR_VIEW_BITS = {"q": 128, "d": 64, "s": 32, "h": 16, "b": 8}


class AArch64MachineDef(PandaMachineDef):
    arch = Architecture.AARCH64
    byteorder = Byteorder.LITTLE

    panda_arch = "aarch64"

    def handle_interrupt(self, intno: int, pc: int) -> None:
        if intno == _ARM_EXCP_PREFETCH_ABORT:
            raise exceptions.EmulationFetchUnmappedFailure(
                f"Fetched unmapped memory at {hex(pc)}", pc, address=pc
            )
        super().handle_interrupt(intno, pc)

    # PANDA's register accessors reach only the general-purpose registers, so
    # the SIMD and FP registers, and cpacr_el1, which gates access to them,
    # live in the CPU state. Vector register n is zregs[n].d[0:2]; its d, s, h
    # and b views are its low bits, and writing one leaves the rest alone.
    # QEMU caches whether the FPU is enabled in the CPU's hflags, so writing
    # cpacr_el1 or fpcr rebuilds them.
    _state_registers = frozenset(
        {"cpacr_el1", "fpcr", "fpsr"}
        | {f"{view}{n}" for view in _VECTOR_VIEW_BITS for n in range(32)}
    )

    def read_state_register(self, name: str, panda_obj, panda_cpu) -> int:
        env = panda_obj.cpu_env(panda_cpu)
        if name == "cpacr_el1":
            return int(env.cp15.cpacr_el1)
        if name == "fpcr":
            return int(panda_obj.libpanda.vfp_get_fpcr(env))
        if name == "fpsr":
            return int(panda_obj.libpanda.vfp_get_fpsr(env))
        lanes = env.vfp.zregs[int(name[1:])].d
        value = int(lanes[0]) | int(lanes[1]) << 64
        return value & ((1 << _VECTOR_VIEW_BITS[name[0]]) - 1)

    def write_state_register(self, name: str, value: int, panda_obj, panda_cpu) -> None:
        env = panda_obj.cpu_env(panda_cpu)
        if name == "cpacr_el1":
            env.cp15.cpacr_el1 = value & 0xFFFFFFFFFFFFFFFF
            panda_obj.libpanda.arm_rebuild_hflags(env)
            return
        if name == "fpcr":
            panda_obj.libpanda.vfp_set_fpcr(env, value & 0xFFFFFFFF)
            panda_obj.libpanda.arm_rebuild_hflags(env)
            return
        if name == "fpsr":
            panda_obj.libpanda.vfp_set_fpsr(env, value & 0xFFFFFFFF)
            return
        lanes = env.vfp.zregs[int(name[1:])].d
        mask = (1 << _VECTOR_VIEW_BITS[name[0]]) - 1
        current = int(lanes[0]) | int(lanes[1]) << 64
        current = (current & ~mask) | (value & mask)
        lanes[0] = current & 0xFFFFFFFFFFFFFFFF
        lanes[1] = current >> 64

    def __init__(self):
        self._registers = {
            "x0": "x0",
            "w0": "x0",
            "x1": "x1",
            "w1": "x1",
            "x2": "x2",
            "w2": "x2",
            "x3": "x3",
            "w3": "x3",
            "x4": "x4",
            "w4": "x4",
            "x5": "x5",
            "w5": "x5",
            "x6": "x6",
            "w6": "x6",
            "x7": "x7",
            "w7": "x7",
            "x8": "xr",
            "w8": "xr",
            "x9": "x9",
            "w9": "x9",
            "x10": "x10",
            "w10": "x10",
            "x11": "x11",
            "w11": "x11",
            "x12": "x12",
            "w12": "x12",
            "x13": "x13",
            "w13": "x13",
            "x14": "x14",
            "w14": "x14",
            "x15": "x15",
            "w15": "x15",
            "x16": "ip0",
            "w16": "ip0",
            "x17": "ip1",
            "w17": "ip1",
            "x18": "pr",
            "w18": "pr",
            "x19": "x19",
            "w19": "x19",
            "x20": "x20",
            "w20": "x20",
            "x21": "x21",
            "w21": "x21",
            "x22": "x22",
            "w22": "x22",
            "x23": "x23",
            "w23": "x23",
            "x24": "x24",
            "w24": "x24",
            "x25": "x25",
            "w25": "x25",
            "x26": "x26",
            "w26": "x26",
            "x27": "x27",
            "w27": "x27",
            "x28": "x28",
            "w28": "x28",
            "x29": "fp",
            "w29": "fp",
            "fp": "fp",
            "x30": "lr",
            "w30": "lr",
            "lr": "lr",
            "pc": "pc",
            "sp": "sp",
            "wsp": "sp",
            "wzr": None,
            "xzr": None,
            "nzcv": None,
            "fpcr": None,
            "fpsr": None,
            "sp_el0": None,
            "sp_el1": None,
            "sp_el2": None,
            "sp_el3": None,
            "elr_el1": None,
            "elr_el2": None,
            "elr_el3": None,
            "far_el1": None,
            "far_el2": None,
            "far_el3": None,
            "vbar_el1": None,
            "vbar_el0": None,
            "vbar_el2": None,
            "vbar_el3": None,
            "cpacr_el1": None,
            "mair_el1": None,
            "par_el1": None,
            "ttbr0_el1": None,
            "ttbr1_el1": None,
            "tpidr_el0": None,
            "tpidr_el1": None,
            "tpidrro_el0": None,
            "q0": None,
            "d0": None,
            "s0": None,
            "h0": None,
            "b0": None,
            "q1": None,
            "d1": None,
            "s1": None,
            "h1": None,
            "b1": None,
            "q2": None,
            "d2": None,
            "s2": None,
            "h2": None,
            "b2": None,
            "q3": None,
            "d3": None,
            "s3": None,
            "h3": None,
            "b3": None,
            "q4": None,
            "d4": None,
            "s4": None,
            "h4": None,
            "b4": None,
            "q5": None,
            "d5": None,
            "s5": None,
            "h5": None,
            "b5": None,
            "q6": None,
            "d6": None,
            "s6": None,
            "h6": None,
            "b6": None,
            "q7": None,
            "d7": None,
            "s7": None,
            "h7": None,
            "b7": None,
            "q8": None,
            "d8": None,
            "s8": None,
            "h8": None,
            "b8": None,
            "q9": None,
            "d9": None,
            "s9": None,
            "h9": None,
            "b9": None,
            "q10": None,
            "d10": None,
            "s10": None,
            "h10": None,
            "b10": None,
            "q11": None,
            "d11": None,
            "s11": None,
            "h11": None,
            "b11": None,
            "q12": None,
            "d12": None,
            "s12": None,
            "h12": None,
            "b12": None,
            "q13": None,
            "d13": None,
            "s13": None,
            "h13": None,
            "b13": None,
            "q14": None,
            "d14": None,
            "s14": None,
            "h14": None,
            "b14": None,
            "q15": None,
            "d15": None,
            "s15": None,
            "h15": None,
            "b15": None,
            "q16": None,
            "d16": None,
            "s16": None,
            "h16": None,
            "b16": None,
            "q17": None,
            "d17": None,
            "s17": None,
            "h17": None,
            "b17": None,
            "q18": None,
            "d18": None,
            "s18": None,
            "h18": None,
            "b18": None,
            "q19": None,
            "d19": None,
            "s19": None,
            "h19": None,
            "b19": None,
            "q20": None,
            "d20": None,
            "s20": None,
            "h20": None,
            "b20": None,
            "q21": None,
            "d21": None,
            "s21": None,
            "h21": None,
            "b21": None,
            "q22": None,
            "d22": None,
            "s22": None,
            "h22": None,
            "b22": None,
            "q23": None,
            "d23": None,
            "s23": None,
            "h23": None,
            "b23": None,
            "q24": None,
            "d24": None,
            "s24": None,
            "h24": None,
            "b24": None,
            "q25": None,
            "d25": None,
            "s25": None,
            "h25": None,
            "b25": None,
            "q26": None,
            "d26": None,
            "s26": None,
            "h26": None,
            "b26": None,
            "q27": None,
            "d27": None,
            "s27": None,
            "h27": None,
            "b27": None,
            "q28": None,
            "d28": None,
            "s28": None,
            "h28": None,
            "b28": None,
            "q29": None,
            "d29": None,
            "s29": None,
            "h29": None,
            "b29": None,
            "q30": None,
            "d30": None,
            "s30": None,
            "h30": None,
            "b30": None,
            "q31": None,
            "d31": None,
            "s31": None,
            "h31": None,
            "b31": None,
        }


class AArch64V85AMachineDef(AArch64MachineDef):
    arch = Architecture.AARCH64_V8_5A
    # QEMU's "max" model accepts a superset of ARMv8.5-A's instructions.
    cpu = "max"


# Big-endian AArch64 keeps its instructions little-endian, as AArch64 always
# does; SCTLR_ELx.EE makes data accesses at ELx big-endian, and SCTLR_EL1.E0E
# those at EL0. PANDA's AArch64 runs at EL3, but every level is set so the
# data stays big-endian at whichever level the code reaches. QEMU caches the
# data endianness in the CPU's hflags, so setting them rebuilds those.

_SCTLR_E0E = 1 << 24
_SCTLR_EE = 1 << 25


class AArch64MachineMixinBE:
    byteorder = Byteorder.BIG

    def configure_cpu(self, panda_obj, panda_cpu) -> None:
        env = panda_obj.cpu_env(panda_cpu)
        for el in range(1, 4):
            env.cp15.sctlr_el[el] |= _SCTLR_EE | _SCTLR_E0E
        panda_obj.libpanda.arm_rebuild_hflags(env)


class AArch64BEMachineDef(AArch64MachineMixinBE, AArch64MachineDef):
    pass


class AArch64V85ABEMachineDef(AArch64MachineMixinBE, AArch64V85AMachineDef):
    pass
