import typing

import capstone

from ..platforms import Architecture, Byteorder
from .platformdef import PlatformDef, RegisterAliasDef, RegisterDef

# PowerPC's register naming convention is extrmely annoying:
# it doesn't have one.
#
# Both the general-purpose registers
# and floating-point registers are solely referenced by number,
# thus making it maddening to tell which one you're talking about.
#
# Also, registers do have special uses within the ABI,
# but aside from sp and bp, they're not really written down.


class PowerPCPlatformDef(PlatformDef):
    byteorder = Byteorder.BIG

    capstone_arch = capstone.CS_ARCH_PPC

    # PowerPC conditional branches are an abject pain.
    # There are 172 possible ways to conditionally branch to an address,
    # and a similar number of ways to branch to LR or CTR.
    # Not all of these have mnemonics, but the ISA doesn't actually specify which.

    # Branch to a label
    _branch_to_label = {
        # Conditional branch
        "bc",
        "beq",
        "bne",
        "blt",
        "ble",
        "bgt",
        "bge",
        "bso",
        "bns",
        # Decrement ctr and branch if non-zero
        # NOTE: This can also include a conditional test
        "bdnz",
        # Decrement ctr and branch if zero
        # NOTE: This can also include a conditional test
        "bdz",
    }
    # Handle "branch-and-link" and "absolute address" variants
    _branch_and_link_to_label = set(map(lambda x: f"{x}l", _branch_to_label))
    _branch_absolute_to_label = set(map(lambda x: f"{x}a", _branch_to_label))
    _branch_and_link_absolute_to_label = set(
        map(lambda x: f"{x}a", _branch_and_link_to_label)
    )

    # Handle branch predictor suggestions
    _branch_to_label_neutral = (
        _branch_to_label
        | _branch_and_link_to_label
        | _branch_absolute_to_label
        | _branch_and_link_absolute_to_label
    )
    _branch_to_label_likely = set(map(lambda x: f"{x}+", _branch_to_label_neutral))
    _branch_to_label_unlikely = set(map(lambda x: f"{x}-", _branch_to_label_neutral))

    # Collect branch to label
    _branch_to_label_all = (
        _branch_to_label_neutral | _branch_to_label_likely | _branch_to_label_unlikely
    )

    # Branch to LR looks the same as branch to label, but with an "lr" suffix after the condition code
    _branch_to_lr = set(map(lambda x: f"{x}lr", _branch_to_label))
    _branch_and_link_to_lr = set(map(lambda x: f"{x}l", _branch_to_lr))

    # Handle branch predictor suggestions
    _branch_to_lr_neutral = _branch_to_lr | _branch_and_link_to_lr
    _branch_to_lr_likely = set(map(lambda x: f"{x}+", _branch_to_lr_neutral))
    _branch_to_lr_unlikely = set(map(lambda x: f"{x}-", _branch_to_lr_neutral))

    # Collect branch to LR
    _branch_to_lr_all = (
        _branch_to_lr_neutral | _branch_to_lr_likely | _branch_to_lr_unlikely
    )

    # Branch to CTR looks the same as branch to label, but with a "ctr" suffix after the condition code.
    _branch_to_ctr = set(map(lambda x: f"{x}ctr", _branch_to_label))
    # There are no mnemonics for using ctr as a counter and branch target at once.
    _branch_to_ctr -= {"bdnzctr", "bdzctr"}
    _branch_and_link_to_ctr = set(map(lambda x: f"{x}l", _branch_to_ctr))

    # Handle branch predictor suggestions
    _branch_to_ctr_neutral = _branch_to_ctr | _branch_and_link_to_ctr
    _branch_to_ctr_likely = set(map(lambda x: f"{x}+", _branch_to_ctr_neutral))
    _branch_to_ctr_unlikely = set(map(lambda x: f"{x}-", _branch_to_ctr_neutral))

    # Collect branch to CTR
    _branch_to_ctr_all = (
        _branch_to_ctr_neutral | _branch_to_ctr_likely | _branch_to_lr_unlikely
    )

    # Finally, collect all conditional branch mnemonics
    conditional_branch_mnemonics = (
        _branch_to_label_all | _branch_to_lr_all | _branch_to_ctr_all
    )

    compare_mnemonics = {
        # Compare registers
        "cmpd",
        "cmpw",
        # Compare immediate
        "cmpi",
        "cmpdi",
        "cmpwi",
        # Compare logical immediate
        "cmpli",
        "cmpldi",
        "cmplwi",
        # Compare
        "cmpl",
        "cmpld",
        "cmplw",
    }

    pc_register = "pc"
    sp_register = "sp"

    # Special registers
    # - r0 and r2 are reserved for the assembler.
    # - r1 is the stack pointer
    # - r31 is the base (frame) pointer
    general_purpose_registers = [f"r{i}" for i in range(3, 31)]

    @property
    def registers(self) -> typing.Dict[str, RegisterDef]:
        return self._registers

    def __init__(self):
        self._registers = {
            # *** General Purpose Registers ***
            # NOTE: Used expressive names for GPRs and FPRs.
            # gasm just refers to GPRs and FPRS by number.
            # They use the same numbers; it's very annoying.
            "r0": RegisterDef(name="r0", size=self.address_size),
            # NOTE: GPR 1 is also the stack pointer.
            "r1": RegisterDef(name="r1", size=self.address_size),
            "sp": RegisterAliasDef("sp", parent="r1", size=self.address_size, offset=0),
            "r2": RegisterDef(name="r2", size=self.address_size),
            "r3": RegisterDef(name="r3", size=self.address_size),
            "r4": RegisterDef(name="r4", size=self.address_size),
            "r5": RegisterDef(name="r5", size=self.address_size),
            "r6": RegisterDef(name="r6", size=self.address_size),
            "r7": RegisterDef(name="r7", size=self.address_size),
            "r8": RegisterDef(name="r8", size=self.address_size),
            "r9": RegisterDef(name="r9", size=self.address_size),
            "r10": RegisterDef(name="r10", size=self.address_size),
            "r11": RegisterDef(name="r11", size=self.address_size),
            "r12": RegisterDef(name="r12", size=self.address_size),
            "r13": RegisterDef(name="r13", size=self.address_size),
            "r14": RegisterDef(name="r14", size=self.address_size),
            "r15": RegisterDef(name="r15", size=self.address_size),
            "r16": RegisterDef(name="r16", size=self.address_size),
            "r17": RegisterDef(name="r17", size=self.address_size),
            "r18": RegisterDef(name="r18", size=self.address_size),
            "r19": RegisterDef(name="r19", size=self.address_size),
            "r20": RegisterDef(name="r20", size=self.address_size),
            "r21": RegisterDef(name="r21", size=self.address_size),
            "r22": RegisterDef(name="r22", size=self.address_size),
            "r23": RegisterDef(name="r23", size=self.address_size),
            "r24": RegisterDef(name="r24", size=self.address_size),
            "r25": RegisterDef(name="r25", size=self.address_size),
            "r26": RegisterDef(name="r26", size=self.address_size),
            "r27": RegisterDef(name="r27", size=self.address_size),
            "r28": RegisterDef(name="r28", size=self.address_size),
            "r29": RegisterDef(name="r29", size=self.address_size),
            "r30": RegisterDef(name="r30", size=self.address_size),
            # NOTE: GPR 31 is also the base pointer
            "r31": RegisterDef(name="r31", size=self.address_size),
            "bp": RegisterAliasDef(
                name="bp", parent="r31", size=self.address_size, offset=0
            ),
            # Floating Point Registers
            # Always 8 bytes, regardless of self.address_size.
            "f0": RegisterDef(name="f0", size=8),
            "f1": RegisterDef(name="f1", size=8),
            "f2": RegisterDef(name="f2", size=8),
            "f3": RegisterDef(name="f3", size=8),
            "f4": RegisterDef(name="f4", size=8),
            "f5": RegisterDef(name="f5", size=8),
            "f6": RegisterDef(name="f6", size=8),
            "f7": RegisterDef(name="f7", size=8),
            "f8": RegisterDef(name="f8", size=8),
            "f9": RegisterDef(name="f9", size=8),
            "f10": RegisterDef(name="f10", size=8),
            "f11": RegisterDef(name="f11", size=8),
            "f12": RegisterDef(name="f12", size=8),
            "f13": RegisterDef(name="f13", size=8),
            "f14": RegisterDef(name="f14", size=8),
            "f15": RegisterDef(name="f15", size=8),
            "f16": RegisterDef(name="f16", size=8),
            "f17": RegisterDef(name="f17", size=8),
            "f18": RegisterDef(name="f18", size=8),
            "f19": RegisterDef(name="f19", size=8),
            "f20": RegisterDef(name="f20", size=8),
            "f21": RegisterDef(name="f21", size=8),
            "f22": RegisterDef(name="f22", size=8),
            "f23": RegisterDef(name="f23", size=8),
            "f24": RegisterDef(name="f24", size=8),
            "f25": RegisterDef(name="f25", size=8),
            "f26": RegisterDef(name="f26", size=8),
            "f27": RegisterDef(name="f27", size=8),
            "f28": RegisterDef(name="f28", size=8),
            "f29": RegisterDef(name="f29", size=8),
            "f30": RegisterDef(name="f30", size=8),
            "f31": RegisterDef(name="f31", size=8),
            # *** Pointer Registers ***
            # Program Counter.
            # Not really a register; nothing can access it directly
            "pc": RegisterDef(name="pc", size=self.address_size),
            # Link Register
            "lr": RegisterDef(name="lr", size=self.address_size),
            # Counter Register
            # Acts either as a loop index, or a branch target register
            # Only `ctr` and `lr` can act as branch targets.
            "ctr": RegisterDef(name="ctr", size=self.address_size),
            # *** Condition Registers ***
            # The actual condition register `cr` is a single 32-bit register,
            # but it's broken into eight 4-bit fields which are accessed separately.
            #
            # Certain operations use specific registers by default,
            # but some tests can specify a destination register.
            "cr0": RegisterDef(name="cr0", size=1),  # Integer condition bits
            "cr1": RegisterDef(name="cr1", size=1),  # Floating point condition bits
            "cr2": RegisterDef(name="cr2", size=1),
            "cr3": RegisterDef(name="cr3", size=1),
            "cr4": RegisterDef(name="cr4", size=1),
            "cr5": RegisterDef(name="cr5", size=1),
            "cr6": RegisterDef(name="cr6", size=1),
            "cr7": RegisterDef(name="cr7", size=1),
            # Integer Exception Register
            # "xer": RegisterDef(name="xer", size=4),
            # Floating Point Status and Control Register
            "fpscr": RegisterDef(name="fpscr", size=4),
            # TODO: This only focuses on the user-facing registrers.
            # ppc has a huge number of privileged registers.
            # Extend this as needed.
            "spr_amor": RegisterDef(name="spr_amor", size=self.address_size)
            "spr_amr": RegisterDef(name="spr_amr", size=self.address_size)
            "spr_atbl": RegisterDef(name="spr_atbl", size=self.address_size)
            "spr_atbu": RegisterDef(name="spr_atbu", size=self.address_size)
            "spr_bamr": RegisterDef(name="spr_bamr", size=self.address_size)
            "spr_bar": RegisterDef(name="spr_bar", size=self.address_size)
            "spr_ccr0": RegisterDef(name="spr_ccr0", size=self.address_size)
            "spr_cmpa": RegisterDef(name="spr_cmpa", size=self.address_size)
            "spr_cmpb": RegisterDef(name="spr_cmpb", size=self.address_size)
            "spr_cmpc": RegisterDef(name="spr_cmpc", size=self.address_size)
            "spr_cmpd": RegisterDef(name="spr_cmpd", size=self.address_size)
            "spr_cmpe": RegisterDef(name="spr_cmpe", size=self.address_size)
            "spr_cmpf": RegisterDef(name="spr_cmpf", size=self.address_size)
            "spr_cmpg": RegisterDef(name="spr_cmpg", size=self.address_size)
            "spr_cmph": RegisterDef(name="spr_cmph", size=self.address_size)
            "spr_counta": RegisterDef(name="spr_counta", size=self.address_size)
            "spr_countb": RegisterDef(name="spr_countb", size=self.address_size)
            "spr_csrr0": RegisterDef(name="spr_csrr0", size=self.address_size)
            "spr_csrr1": RegisterDef(name="spr_csrr1", size=self.address_size)
            "spr_ctr": RegisterDef(name="spr_ctr", size=self.address_size)
            "spr_dabr": RegisterDef(name="spr_dabr", size=self.address_size)
            "spr_dabr2": RegisterDef(name="spr_dabr2", size=self.address_size)
            "spr_dac1": RegisterDef(name="spr_dac1", size=self.address_size)
            "spr_dac2": RegisterDef(name="spr_dac2", size=self.address_size)
            "spr_dacr": RegisterDef(name="spr_dacr", size=self.address_size)
            "spr_dar": RegisterDef(name="spr_dar", size=self.address_size)
            "spr_dbat0l": RegisterDef(name="spr_dbat0l", size=self.address_size)
            "spr_dbat0u": RegisterDef(name="spr_dbat0u", size=self.address_size)
            "spr_dbat1l": RegisterDef(name="spr_dbat1l", size=self.address_size)
            "spr_dbat1u": RegisterDef(name="spr_dbat1u", size=self.address_size)
            "spr_dbat2l": RegisterDef(name="spr_dbat2l", size=self.address_size)
            "spr_dbat2u": RegisterDef(name="spr_dbat2u", size=self.address_size)
            "spr_dbat3l": RegisterDef(name="spr_dbat3l", size=self.address_size)
            "spr_dbat3u": RegisterDef(name="spr_dbat3u", size=self.address_size)
            "spr_dbat4l": RegisterDef(name="spr_dbat4l", size=self.address_size)
            "spr_dbat4u": RegisterDef(name="spr_dbat4u", size=self.address_size)
            "spr_dbat5l": RegisterDef(name="spr_dbat5l", size=self.address_size)
            "spr_dbat5u": RegisterDef(name="spr_dbat5u", size=self.address_size)
            "spr_dbat6l": RegisterDef(name="spr_dbat6l", size=self.address_size)
            "spr_dbat6u": RegisterDef(name="spr_dbat6u", size=self.address_size)
            "spr_dbat7l": RegisterDef(name="spr_dbat7l", size=self.address_size)
            "spr_dbat7u": RegisterDef(name="spr_dbat7u", size=self.address_size)
            "spr_dbcr": RegisterDef(name="spr_dbcr", size=self.address_size)
            "spr_dbcr0": RegisterDef(name="spr_dbcr0", size=self.address_size)
            "spr_dbcr1": RegisterDef(name="spr_dbcr1", size=self.address_size)
            "spr_dbcr2": RegisterDef(name="spr_dbcr2", size=self.address_size)
            "spr_dbdr": RegisterDef(name="spr_dbdr", size=self.address_size)
            "spr_dbsr": RegisterDef(name="spr_dbsr", size=self.address_size)
            "spr_dccr": RegisterDef(name="spr_dccr", size=self.address_size)
            "spr_dcdbtrh": RegisterDef(name="spr_dcdbtrh", size=self.address_size)
            "spr_dcdbtrl": RegisterDef(name="spr_dcdbtrl", size=self.address_size)
            "spr_dcmp": RegisterDef(name="spr_dcmp", size=self.address_size)
            "spr_dcwr": RegisterDef(name="spr_dcwr", size=self.address_size)
            "spr_dc_adr": RegisterDef(name="spr_dc_adr", size=self.address_size)
            "spr_dc_cst": RegisterDef(name="spr_dc_cst", size=self.address_size)
            "spr_dc_dat": RegisterDef(name="spr_dc_dat", size=self.address_size)
            "spr_dear": RegisterDef(name="spr_dear", size=self.address_size)
            "spr_dec": RegisterDef(name="spr_dec", size=self.address_size)
            "spr_decar": RegisterDef(name="spr_decar", size=self.address_size)
            "spr_decr": RegisterDef(name="spr_decr", size=self.address_size)
            "spr_der": RegisterDef(name="spr_der", size=self.address_size)
            "spr_dmiss": RegisterDef(name="spr_dmiss", size=self.address_size)
            "spr_dnv0": RegisterDef(name="spr_dnv0", size=self.address_size)
            "spr_dnv1": RegisterDef(name="spr_dnv1", size=self.address_size)
            "spr_dnv2": RegisterDef(name="spr_dnv2", size=self.address_size)
            "spr_dnv3": RegisterDef(name="spr_dnv3", size=self.address_size)
            "spr_dpdr": RegisterDef(name="spr_dpdr", size=self.address_size)
            "spr_dsisr": RegisterDef(name="spr_dsisr", size=self.address_size)
            "spr_dsrr0": RegisterDef(name="spr_dsrr0", size=self.address_size)
            "spr_dsrr1": RegisterDef(name="spr_dsrr1", size=self.address_size)
            "spr_dtv0": RegisterDef(name="spr_dtv0", size=self.address_size)
            "spr_dtv1": RegisterDef(name="spr_dtv1", size=self.address_size)
            "spr_dtv2": RegisterDef(name="spr_dtv2", size=self.address_size)
            "spr_dtv3": RegisterDef(name="spr_dtv3", size=self.address_size)
            "spr_dvc1": RegisterDef(name="spr_dvc1", size=self.address_size)
            "spr_dvc2": RegisterDef(name="spr_dvc2", size=self.address_size)
            "spr_dvlim": RegisterDef(name="spr_dvlim", size=self.address_size)
            "spr_ear": RegisterDef(name="spr_ear", size=self.address_size)
            "spr_ecr": RegisterDef(name="spr_ecr", size=self.address_size)
            "spr_edr": RegisterDef(name="spr_edr", size=self.address_size)
            "spr_eid": RegisterDef(name="spr_eid", size=self.address_size)
            "spr_eie": RegisterDef(name="spr_eie", size=self.address_size)
            "spr_eplc": RegisterDef(name="spr_eplc", size=self.address_size)
            "spr_epsc": RegisterDef(name="spr_epsc", size=self.address_size)
            "spr_esr": RegisterDef(name="spr_esr", size=self.address_size)
            "spr_evpr": RegisterDef(name="spr_evpr", size=self.address_size)
            "spr_fpecr": RegisterDef(name="spr_fpecr", size=self.address_size)
            "spr_hash1": RegisterDef(name="spr_hash1", size=self.address_size)
            "spr_hash2": RegisterDef(name="spr_hash2", size=self.address_size)
            "spr_hid0": RegisterDef(name="spr_hid0", size=self.address_size)
            "spr_hid1": RegisterDef(name="spr_hid1", size=self.address_size)
            "spr_hid2": RegisterDef(name="spr_hid2", size=self.address_size)
            "spr_iabr": RegisterDef(name="spr_iabr", size=self.address_size)
            "spr_iabr2": RegisterDef(name="spr_iabr2", size=self.address_size)
            "spr_iac1": RegisterDef(name="spr_iac1", size=self.address_size)
            "spr_iac2": RegisterDef(name="spr_iac2", size=self.address_size)
            "spr_iac3": RegisterDef(name="spr_iac3", size=self.address_size)
            "spr_iac4": RegisterDef(name="spr_iac4", size=self.address_size)
            "spr_iamr": RegisterDef(name="spr_iamr", size=self.address_size)
            "spr_ibat0l": RegisterDef(name="spr_ibat0l", size=self.address_size)
            "spr_ibat0u": RegisterDef(name="spr_ibat0u", size=self.address_size)
            "spr_ibat1l": RegisterDef(name="spr_ibat1l", size=self.address_size)
            "spr_ibat1u": RegisterDef(name="spr_ibat1u", size=self.address_size)
            "spr_ibat2l": RegisterDef(name="spr_ibat2l", size=self.address_size)
            "spr_ibat2u": RegisterDef(name="spr_ibat2u", size=self.address_size)
            "spr_ibat3l": RegisterDef(name="spr_ibat3l", size=self.address_size)
            "spr_ibat3u": RegisterDef(name="spr_ibat3u", size=self.address_size)
            "spr_ibat4l": RegisterDef(name="spr_ibat4l", size=self.address_size)
            "spr_ibat4u": RegisterDef(name="spr_ibat4u", size=self.address_size)
            "spr_ibat5l": RegisterDef(name="spr_ibat5l", size=self.address_size)
            "spr_ibat5u": RegisterDef(name="spr_ibat5u", size=self.address_size)
            "spr_ibat6l": RegisterDef(name="spr_ibat6l", size=self.address_size)
            "spr_ibat6u": RegisterDef(name="spr_ibat6u", size=self.address_size)
            "spr_ibat7l": RegisterDef(name="spr_ibat7l", size=self.address_size)
            "spr_ibat7u": RegisterDef(name="spr_ibat7u", size=self.address_size)
            "spr_ibcr": RegisterDef(name="spr_ibcr", size=self.address_size)
            "spr_iccr": RegisterDef(name="spr_iccr", size=self.address_size)
            "spr_icdbdr": RegisterDef(name="spr_icdbdr", size=self.address_size)
            "spr_icdbtrh": RegisterDef(name="spr_icdbtrh", size=self.address_size)
            "spr_icdbtrl": RegisterDef(name="spr_icdbtrl", size=self.address_size)
            "spr_icmp": RegisterDef(name="spr_icmp", size=self.address_size)
            "spr_ictc": RegisterDef(name="spr_ictc", size=self.address_size)
            "spr_ic_adr": RegisterDef(name="spr_ic_adr", size=self.address_size)
            "spr_ic_cst": RegisterDef(name="spr_ic_cst", size=self.address_size)
            "spr_ic_dat": RegisterDef(name="spr_ic_dat", size=self.address_size)
            "spr_imiss": RegisterDef(name="spr_imiss", size=self.address_size)
            "spr_immr": RegisterDef(name="spr_immr", size=self.address_size)
            "spr_inv0": RegisterDef(name="spr_inv0", size=self.address_size)
            "spr_inv1": RegisterDef(name="spr_inv1", size=self.address_size)
            "spr_inv2": RegisterDef(name="spr_inv2", size=self.address_size)
            "spr_inv3": RegisterDef(name="spr_inv3", size=self.address_size)
            "spr_isr": RegisterDef(name="spr_isr", size=self.address_size)
            "spr_itv0": RegisterDef(name="spr_itv0", size=self.address_size)
            "spr_itv1": RegisterDef(name="spr_itv1", size=self.address_size)
            "spr_itv2": RegisterDef(name="spr_itv2", size=self.address_size)
            "spr_itv3": RegisterDef(name="spr_itv3", size=self.address_size)
            "spr_ivlim": RegisterDef(name="spr_ivlim", size=self.address_size)
            "spr_ivor0": RegisterDef(name="spr_ivor0", size=self.address_size)
            "spr_ivor1": RegisterDef(name="spr_ivor1", size=self.address_size)
            "spr_ivor10": RegisterDef(name="spr_ivor10", size=self.address_size)
            "spr_ivor11": RegisterDef(name="spr_ivor11", size=self.address_size)
            "spr_ivor12": RegisterDef(name="spr_ivor12", size=self.address_size)
            "spr_ivor13": RegisterDef(name="spr_ivor13", size=self.address_size)
            "spr_ivor14": RegisterDef(name="spr_ivor14", size=self.address_size)
            "spr_ivor15": RegisterDef(name="spr_ivor15", size=self.address_size)
            "spr_ivor16": RegisterDef(name="spr_ivor16", size=self.address_size)
            "spr_ivor17": RegisterDef(name="spr_ivor17", size=self.address_size)
            "spr_ivor18": RegisterDef(name="spr_ivor18", size=self.address_size)
            "spr_ivor19": RegisterDef(name="spr_ivor19", size=self.address_size)
            "spr_ivor2": RegisterDef(name="spr_ivor2", size=self.address_size)
            "spr_ivor20": RegisterDef(name="spr_ivor20", size=self.address_size)
            "spr_ivor21": RegisterDef(name="spr_ivor21", size=self.address_size)
            "spr_ivor22": RegisterDef(name="spr_ivor22", size=self.address_size)
            "spr_ivor23": RegisterDef(name="spr_ivor23", size=self.address_size)
            "spr_ivor24": RegisterDef(name="spr_ivor24", size=self.address_size)
            "spr_ivor25": RegisterDef(name="spr_ivor25", size=self.address_size)
            "spr_ivor26": RegisterDef(name="spr_ivor26", size=self.address_size)
            "spr_ivor27": RegisterDef(name="spr_ivor27", size=self.address_size)
            "spr_ivor28": RegisterDef(name="spr_ivor28", size=self.address_size)
            "spr_ivor29": RegisterDef(name="spr_ivor29", size=self.address_size)
            "spr_ivor3": RegisterDef(name="spr_ivor3", size=self.address_size)
            "spr_ivor30": RegisterDef(name="spr_ivor30", size=self.address_size)
            "spr_ivor31": RegisterDef(name="spr_ivor31", size=self.address_size)
            "spr_ivor32": RegisterDef(name="spr_ivor32", size=self.address_size)
            "spr_ivor33": RegisterDef(name="spr_ivor33", size=self.address_size)
            "spr_ivor34": RegisterDef(name="spr_ivor34", size=self.address_size)
            "spr_ivor35": RegisterDef(name="spr_ivor35", size=self.address_size)
            "spr_ivor36": RegisterDef(name="spr_ivor36", size=self.address_size)
            "spr_ivor37": RegisterDef(name="spr_ivor37", size=self.address_size)
            "spr_ivor38": RegisterDef(name="spr_ivor38", size=self.address_size)
            "spr_ivor39": RegisterDef(name="spr_ivor39", size=self.address_size)
            "spr_ivor4": RegisterDef(name="spr_ivor4", size=self.address_size)
            "spr_ivor40": RegisterDef(name="spr_ivor40", size=self.address_size)
            "spr_ivor41": RegisterDef(name="spr_ivor41", size=self.address_size)
            "spr_ivor42": RegisterDef(name="spr_ivor42", size=self.address_size)
            "spr_ivor43": RegisterDef(name="spr_ivor43", size=self.address_size)
            "spr_ivor44": RegisterDef(name="spr_ivor44", size=self.address_size)
            "spr_ivor45": RegisterDef(name="spr_ivor45", size=self.address_size)
            "spr_ivor46": RegisterDef(name="spr_ivor46", size=self.address_size)
            "spr_ivor47": RegisterDef(name="spr_ivor47", size=self.address_size)
            "spr_ivor48": RegisterDef(name="spr_ivor48", size=self.address_size)
            "spr_ivor49": RegisterDef(name="spr_ivor49", size=self.address_size)
            "spr_ivor5": RegisterDef(name="spr_ivor5", size=self.address_size)
            "spr_ivor50": RegisterDef(name="spr_ivor50", size=self.address_size)
            "spr_ivor51": RegisterDef(name="spr_ivor51", size=self.address_size)
            "spr_ivor52": RegisterDef(name="spr_ivor52", size=self.address_size)
            "spr_ivor53": RegisterDef(name="spr_ivor53", size=self.address_size)
            "spr_ivor54": RegisterDef(name="spr_ivor54", size=self.address_size)
            "spr_ivor55": RegisterDef(name="spr_ivor55", size=self.address_size)
            "spr_ivor56": RegisterDef(name="spr_ivor56", size=self.address_size)
            "spr_ivor57": RegisterDef(name="spr_ivor57", size=self.address_size)
            "spr_ivor58": RegisterDef(name="spr_ivor58", size=self.address_size)
            "spr_ivor59": RegisterDef(name="spr_ivor59", size=self.address_size)
            "spr_ivor6": RegisterDef(name="spr_ivor6", size=self.address_size)
            "spr_ivor60": RegisterDef(name="spr_ivor60", size=self.address_size)
            "spr_ivor61": RegisterDef(name="spr_ivor61", size=self.address_size)
            "spr_ivor62": RegisterDef(name="spr_ivor62", size=self.address_size)
            "spr_ivor63": RegisterDef(name="spr_ivor63", size=self.address_size)
            "spr_ivor7": RegisterDef(name="spr_ivor7", size=self.address_size)
            "spr_ivor8": RegisterDef(name="spr_ivor8", size=self.address_size)
            "spr_ivor9": RegisterDef(name="spr_ivor9", size=self.address_size)
            "spr_ivpr": RegisterDef(name="spr_ivpr", size=self.address_size)
            "spr_l2cr": RegisterDef(name="spr_l2cr", size=self.address_size)
            "spr_l2pmcr": RegisterDef(name="spr_l2pmcr", size=self.address_size)
            "spr_l2u_bbcmcr": RegisterDef(name="spr_l2u_bbcmcr", size=self.address_size)
            "spr_l2u_gra": RegisterDef(name="spr_l2u_gra", size=self.address_size)
            "spr_l2u_mcr": RegisterDef(name="spr_l2u_mcr", size=self.address_size)
            "spr_l2u_ra0": RegisterDef(name="spr_l2u_ra0", size=self.address_size)
            "spr_l2u_ra1": RegisterDef(name="spr_l2u_ra1", size=self.address_size)
            "spr_l2u_ra2": RegisterDef(name="spr_l2u_ra2", size=self.address_size)
            "spr_l2u_ra3": RegisterDef(name="spr_l2u_ra3", size=self.address_size)
            "spr_l2u_rba0": RegisterDef(name="spr_l2u_rba0", size=self.address_size)
            "spr_l2u_rba1": RegisterDef(name="spr_l2u_rba1", size=self.address_size)
            "spr_l2u_rba2": RegisterDef(name="spr_l2u_rba2", size=self.address_size)
            "spr_l2u_rba3": RegisterDef(name="spr_l2u_rba3", size=self.address_size)
            "spr_l3cr": RegisterDef(name="spr_l3cr", size=self.address_size)
            "spr_l3itcr0": RegisterDef(name="spr_l3itcr0", size=self.address_size)
            "spr_l3pm": RegisterDef(name="spr_l3pm", size=self.address_size)
            "spr_lctrl1": RegisterDef(name="spr_lctrl1", size=self.address_size)
            "spr_lctrl2": RegisterDef(name="spr_lctrl2", size=self.address_size)
            "spr_lr": RegisterDef(name="spr_lr", size=self.address_size)
            "spr_mas0": RegisterDef(name="spr_mas0", size=self.address_size)
            "spr_mas1": RegisterDef(name="spr_mas1", size=self.address_size)
            "spr_mas2": RegisterDef(name="spr_mas2", size=self.address_size)
            "spr_mas3": RegisterDef(name="spr_mas3", size=self.address_size)
            "spr_mas4": RegisterDef(name="spr_mas4", size=self.address_size)
            "spr_mas5": RegisterDef(name="spr_mas5", size=self.address_size)
            "spr_mas6": RegisterDef(name="spr_mas6", size=self.address_size)
            "spr_mas7": RegisterDef(name="spr_mas7", size=self.address_size)
            "spr_mbar": RegisterDef(name="spr_mbar", size=self.address_size)
            "spr_md_ap": RegisterDef(name="spr_md_ap", size=self.address_size)
            "spr_md_casid": RegisterDef(name="spr_md_casid", size=self.address_size)
            "spr_md_ctr": RegisterDef(name="spr_md_ctr", size=self.address_size)
            "spr_md_dbcam": RegisterDef(name="spr_md_dbcam", size=self.address_size)
            "spr_md_dbram0": RegisterDef(name="spr_md_dbram0", size=self.address_size)
            "spr_md_dbram1": RegisterDef(name="spr_md_dbram1", size=self.address_size)
            "spr_md_epn": RegisterDef(name="spr_md_epn", size=self.address_size)
            "spr_md_rpn": RegisterDef(name="spr_md_rpn", size=self.address_size)
            "spr_md_tw": RegisterDef(name="spr_md_tw", size=self.address_size)
            "spr_md_twb": RegisterDef(name="spr_md_twb", size=self.address_size)
            "spr_md_twc": RegisterDef(name="spr_md_twc", size=self.address_size)
            "spr_mi_ap": RegisterDef(name="spr_mi_ap", size=self.address_size)
            "spr_mi_ctr": RegisterDef(name="spr_mi_ctr", size=self.address_size)
            "spr_mi_dbcam": RegisterDef(name="spr_mi_dbcam", size=self.address_size)
            "spr_mi_dbram0": RegisterDef(name="spr_mi_dbram0", size=self.address_size)
            "spr_mi_dbram1": RegisterDef(name="spr_mi_dbram1", size=self.address_size)
            "spr_mi_epn": RegisterDef(name="spr_mi_epn", size=self.address_size)
            "spr_mi_gra": RegisterDef(name="spr_mi_gra", size=self.address_size)
            "spr_mi_ra0": RegisterDef(name="spr_mi_ra0", size=self.address_size)
            "spr_mi_ra1": RegisterDef(name="spr_mi_ra1", size=self.address_size)
            "spr_mi_ra2": RegisterDef(name="spr_mi_ra2", size=self.address_size)
            "spr_mi_ra3": RegisterDef(name="spr_mi_ra3", size=self.address_size)
            "spr_mi_rba0": RegisterDef(name="spr_mi_rba0", size=self.address_size)
            "spr_mi_rba1": RegisterDef(name="spr_mi_rba1", size=self.address_size)
            "spr_mi_rba2": RegisterDef(name="spr_mi_rba2", size=self.address_size)
            "spr_mi_rba3": RegisterDef(name="spr_mi_rba3", size=self.address_size)
            "spr_mi_rpn": RegisterDef(name="spr_mi_rpn", size=self.address_size)
            "spr_mi_twc": RegisterDef(name="spr_mi_twc", size=self.address_size)
            "spr_mmcr0": RegisterDef(name="spr_mmcr0", size=self.address_size)
            "spr_mmcr1": RegisterDef(name="spr_mmcr1", size=self.address_size)
            "spr_mmcr2": RegisterDef(name="spr_mmcr2", size=self.address_size)
            "spr_mmucfg": RegisterDef(name="spr_mmucfg", size=self.address_size)
            "spr_mmucr": RegisterDef(name="spr_mmucr", size=self.address_size)
            "spr_msscr0": RegisterDef(name="spr_msscr0", size=self.address_size)
            "spr_nri": RegisterDef(name="spr_nri", size=self.address_size)
            "spr_pid": RegisterDef(name="spr_pid", size=self.address_size)
            "spr_pid1": RegisterDef(name="spr_pid1", size=self.address_size)
            "spr_pid2": RegisterDef(name="spr_pid2", size=self.address_size)
            "spr_pir": RegisterDef(name="spr_pir", size=self.address_size)
            "spr_pit": RegisterDef(name="spr_pit", size=self.address_size)
            "spr_pmc1": RegisterDef(name="spr_pmc1", size=self.address_size)
            "spr_pmc2": RegisterDef(name="spr_pmc2", size=self.address_size)
            "spr_pmc3": RegisterDef(name="spr_pmc3", size=self.address_size)
            "spr_pmc4": RegisterDef(name="spr_pmc4", size=self.address_size)
            "spr_pvr": RegisterDef(name="spr_pvr", size=self.address_size)
            "spr_rpa": RegisterDef(name="spr_rpa", size=self.address_size)
            "spr_rstcfg": RegisterDef(name="spr_rstcfg", size=self.address_size)
            "spr_sda": RegisterDef(name="spr_sda", size=self.address_size)
            "spr_sdr1": RegisterDef(name="spr_sdr1", size=self.address_size)
            "spr_sgr": RegisterDef(name="spr_sgr", size=self.address_size)
            "spr_siar": RegisterDef(name="spr_siar", size=self.address_size)
            "spr_sler": RegisterDef(name="spr_sler", size=self.address_size)
            "spr_sprg0": RegisterDef(name="spr_sprg0", size=self.address_size)
            "spr_sprg1": RegisterDef(name="spr_sprg1", size=self.address_size)
            "spr_sprg2": RegisterDef(name="spr_sprg2", size=self.address_size)
            "spr_sprg3": RegisterDef(name="spr_sprg3", size=self.address_size)
            "spr_sprg4": RegisterDef(name="spr_sprg4", size=self.address_size)
            "spr_sprg5": RegisterDef(name="spr_sprg5", size=self.address_size)
            "spr_sprg6": RegisterDef(name="spr_sprg6", size=self.address_size)
            "spr_sprg7": RegisterDef(name="spr_sprg7", size=self.address_size)
            "spr_sprg8": RegisterDef(name="spr_sprg8", size=self.address_size)
            "spr_sprg9": RegisterDef(name="spr_sprg9", size=self.address_size)
            "spr_srr0": RegisterDef(name="spr_srr0", size=self.address_size)
            "spr_srr1": RegisterDef(name="spr_srr1", size=self.address_size)
            "spr_srr2": RegisterDef(name="spr_srr2", size=self.address_size)
            "spr_srr3": RegisterDef(name="spr_srr3", size=self.address_size)
            "spr_su0r": RegisterDef(name="spr_su0r", size=self.address_size)
            "spr_svr": RegisterDef(name="spr_svr", size=self.address_size)
            "spr_tbl": RegisterDef(name="spr_tbl", size=self.address_size)
            "spr_tbu": RegisterDef(name="spr_tbu", size=self.address_size)
            "spr_tcr": RegisterDef(name="spr_tcr", size=self.address_size)
            "spr_thrm1": RegisterDef(name="spr_thrm1", size=self.address_size)
            "spr_thrm2": RegisterDef(name="spr_thrm2", size=self.address_size)
            "spr_thrm3": RegisterDef(name="spr_thrm3", size=self.address_size)
            "spr_tlb0cfg": RegisterDef(name="spr_tlb0cfg", size=self.address_size)
            "spr_tlb1cfg": RegisterDef(name="spr_tlb1cfg", size=self.address_size)
            "spr_tsr": RegisterDef(name="spr_tsr", size=self.address_size)
            "spr_uamor": RegisterDef(name="spr_uamor", size=self.address_size)
            "spr_uamr": RegisterDef(name="spr_uamr", size=self.address_size)
            "spr_ummcr0": RegisterDef(name="spr_ummcr0", size=self.address_size)
            "spr_ummcr1": RegisterDef(name="spr_ummcr1", size=self.address_size)
            "spr_ummcr2": RegisterDef(name="spr_ummcr2", size=self.address_size)
            "spr_upmc1": RegisterDef(name="spr_upmc1", size=self.address_size)
            "spr_upmc2": RegisterDef(name="spr_upmc2", size=self.address_size)
            "spr_upmc3": RegisterDef(name="spr_upmc3", size=self.address_size)
            "spr_upmc4": RegisterDef(name="spr_upmc4", size=self.address_size)
            "spr_usiar": RegisterDef(name="spr_usiar", size=self.address_size)
            "spr_usprg0": RegisterDef(name="spr_usprg0", size=self.address_size)
            "spr_usprg4": RegisterDef(name="spr_usprg4", size=self.address_size)
            "spr_usprg5": RegisterDef(name="spr_usprg5", size=self.address_size)
            "spr_usprg6": RegisterDef(name="spr_usprg6", size=self.address_size)
            "spr_usprg7": RegisterDef(name="spr_usprg7", size=self.address_size)
            "spr_vrsave": RegisterDef(name="spr_vrsave", size=self.address_size)
            "spr_xer": RegisterDef(name="spr_xer", size=self.address_size)
            "spr_zpr": RegisterDef(name="spr_zpr", size=self.address_size)

        }


class PowerPC32(PowerPCPlatformDef):
    architecture = Architecture.POWERPC32

    address_size = 4
    capstone_mode = capstone.CS_MODE_32 | capstone.CS_MODE_BIG_ENDIAN


class PowerPC64(PowerPCPlatformDef):
    architecture = Architecture.POWERPC64

    address_size = 8
    capstone_mode = capstone.CS_MODE_64 | capstone.CS_MODE_BIG_ENDIAN
