import capstone

from ..platforms import Architecture, Byteorder
from .platformdef import PlatformDef, RegisterAliasDef, RegisterDef


class I386(PlatformDef):
    architecture = Architecture.X86_32
    byteorder = Byteorder.LITTLE

    address_size = 4

    capstone_arch = capstone.CS_ARCH_X86
    capstone_mode = capstone.CS_MODE_32

    conditional_branch_mnemonics = {
        # All 57 varieties of Jcc opcode
        "jo",
        "jno",
        "jb",
        "jnae",
        "jc",
        "jnb",
        "jae",
        "jnc",
        "jz",
        "je",
        "jnz",
        "jne",
        "jbe",
        "jna",
        "jnbe",
        "ja",
        "js",
        "jns",
        "jp",
        "jpe",
        "jnp",
        "jpo",
        "jl",
        "jnge",
        "jnl",
        "jge",
        "jle",
        "jng",
        "jnle",
        "jg",
        # Jump if (re)?cx is zero
        # Oddly I can't find this in the opcode tables;
        # it's mentioned tangentially in the docs for Jcc
        # (and it's accepted by the assembler.)
        "jrcxz",
        "jecxz",
        "jcxz",
    }
    # TODO: Should arithmetic operations that impact flags be compares?
    compare_mnemonics = {
        # Basic integer comparisons.
        "cmp",
        "test",
        # SIMD float comparisons
        # 'pd' and 'ps' variants work on packed double and packed single floats.
        # TODO I'm not sure how this extends for AVX2 registers
        # NOTE: There's another, less-descriptive way to decode these
        # what does capstone use?
        "cmpeqpd",
        "cmpeqps",
        "cmpltpd",
        "cmpltps",
        "cmplepd",
        "cmpleps",
        "cmpunordpd",
        "cmpunordps",
        "cmpneqpd",
        "cmpneqps",
        "cmpnltpd",
        "cmpnltps",
        "cmpnlepd",
        "cmpnleps",
        "cmpordpd",
        "cmpordps",
        # Compare string operands
        "cmps",
        "cmpsw",
        "cmpsd",
        "cmpsq",
        # Single float comparisons
        # 'sd' and 'ss' variants work on double and single-precision floats.
        # TODO: I'm not sure how this extends for AVX2 registers
        "cmpeqsd",
        "cmpeqss",
        "cmpltsd",
        "cmpltss",
        "cmplesd",
        "cmpless",
        "cmpunordsd",
        "cmpunordss",
        "cmpneqsd",
        "cmpneqss",
        "cmpnltsd",
        "cmpnltss",
        "cmpnlesd",
        "cmpnless",
        "cmpordsd",
        "cmpordss",
        # TODO: Do cmpxchg, cmpxchg8b, cmpxchg16b count?
        # Generic float comparison
        # Unlike previous lists, sets multiple flags depending.
        "comisd",
        "comiss",
        # x87 float comparison
        # Sets FPU condition flags
        "fcom",
        "fcomp",
        "fcompp",
        # x87 float comparison
        # Sets eflags
        "fcomi",
        "fcomip",
        "fcomipp",
        # x87 integer comparison
        "ficom",
        "ficomp",
        # x87 test (comparison against zero)
        # Sets FPU condition flags
        "ftst",
        # x87 float comparison
        # Sets FPU condition flags
        # Behaves differently with NaNs
        "fucom",
        "fucomp",
        "fucompp",
        # x87 examine float
        # Sets FPU flags according to which type of float this is (normal, zero, NaN, infty...)
        "fxam",
        # TODO: There may be more of these... waiting...
    }

    pc_register = "eip"
    sp_register = "esp"

    # NOTE: ebp and esp are not considered general.
    # You _can_ use them as GPRs; it's very rarely a good idea.
    general_purpose_registers = ["eax", "ebx", "ecx", "edx", "edi", "esi"]

    registers = {
        "eax": RegisterDef(name="eax", size=4),
        "ax": RegisterAliasDef(name="ax", parent="eax", size=2, offset=0),
        "al": RegisterAliasDef(name="al", parent="eax", size=1, offset=0),
        "ah": RegisterAliasDef(name="ah", parent="eax", size=1, offset=1),
        "ebx": RegisterDef(name="ebx", size=4),
        "bx": RegisterAliasDef(name="bx", parent="ebx", size=2, offset=0),
        "bl": RegisterAliasDef(name="bl", parent="ebx", size=1, offset=0),
        "bh": RegisterAliasDef(name="bh", parent="ebx", size=1, offset=1),
        "ecx": RegisterDef(name="ecx", size=4),
        "cx": RegisterAliasDef(name="cx", parent="ecx", size=2, offset=0),
        "cl": RegisterAliasDef(name="cl", parent="ecx", size=1, offset=0),
        "ch": RegisterAliasDef(name="ch", parent="ecx", size=1, offset=1),
        "edx": RegisterDef(name="edx", size=4),
        "dx": RegisterAliasDef(name="dx", parent="edx", size=2, offset=0),
        "dl": RegisterAliasDef(name="dl", parent="edx", size=1, offset=0),
        "dh": RegisterAliasDef(name="dh", parent="edx", size=1, offset=1),
        "esi": RegisterDef(name="esi", size=4),
        "si": RegisterAliasDef(name="si", parent="esi", size=2, offset=0),
        "sil": RegisterAliasDef(name="sil", parent="esi", size=1, offset=0),
        "edi": RegisterDef(name="edi", size=4),
        "di": RegisterAliasDef(name="di", parent="edi", size=2, offset=0),
        "dil": RegisterAliasDef(name="dil", parent="edi", size=1, offset=0),
        "ebp": RegisterDef(name="ebp", size=4),
        "bp": RegisterAliasDef(name="bp", parent="ebp", size=2, offset=0),
        "bpl": RegisterAliasDef(name="bpl", parent="ebp", size=1, offset=0),
        "esp": RegisterDef(name="esp", size=4),
        "sp": RegisterAliasDef(name="sp", parent="esp", size=2, offset=0),
        "spl": RegisterAliasDef(name="spl", parent="esp", size=1, offset=0),
        # *** Instruction Pointer ***
        "eip": RegisterDef(name="eip", size=4),
        "ip": RegisterAliasDef(name="ip", parent="eip", size=2, offset=0),
        "pc": RegisterAliasDef(name="pc", parent="eip", size=4, offset=0),
        # *** Segment Registers ***
        "cs": RegisterDef(name="cs", size=2),
        "ss": RegisterDef(name="ss", size=2),
        "ds": RegisterDef(name="ds", size=2),
        "es": RegisterDef(name="es", size=2),
        "fs": RegisterDef(name="fs", size=2),
        "gs": RegisterDef(name="gs", size=2),
        # *** Flags Registers ***
        "eflags": RegisterDef(name="eflags", size=4),
        "flags": RegisterAliasDef(name="flags", parent="eflags", size=2, offset=0),
        # *** Control Registers ***
        "cr0": RegisterDef(name="cr0", size=4),
        "cr1": RegisterDef(name="cr1", size=4),
        "cr2": RegisterDef(name="cr2", size=4),
        "cr3": RegisterDef(name="cr3", size=4),
        "cr4": RegisterDef(name="cr4", size=4),
        # NOTE: I've got conflicting reports whether cr8 exists in i386.
        "cr8": RegisterDef(name="cr8", size=4),
        # *** Debug Registers ***
        "dr0": RegisterDef(name="dr0", size=4),
        "dr1": RegisterDef(name="dr1", size=4),
        "dr2": RegisterDef(name="dr2", size=4),
        "dr3": RegisterDef(name="dr3", size=4),
        "dr6": RegisterDef(name="dr6", size=4),
        "dr7": RegisterDef(name="dr7", size=4),
        # *** Descriptor Table Registers
        # NOTE: Yes, this is 6 bytes; 2 byte segment selector plus 4 byte offset
        "gdtr": RegisterDef(name="gdtr", size=6),
        "idtr": RegisterDef(name="idtr", size=6),
        "ldtr": RegisterDef(name="ldtr", size=6),
        # *** Task Register ***
        # NOTE: Yes, this is 6 bytes; 2 byte segment selector plus 4 byte offset
        "tr": RegisterDef(name="tr", size=6),
        # *** x87 registers ***
        "fpr0": RegisterDef(name="fpr0", size=10),
        "fpr1": RegisterDef(name="fpr1", size=10),
        "fpr2": RegisterDef(name="fpr2", size=10),
        "fpr3": RegisterDef(name="fpr3", size=10),
        "fpr4": RegisterDef(name="fpr4", size=10),
        "fpr5": RegisterDef(name="fpr5", size=10),
        "fpr6": RegisterDef(name="fpr6", size=10),
        "fpr7": RegisterDef(name="fpr7", size=10),
        # x87 Control Register
        "fctrl": RegisterDef(name="fctrl", size=2),
        # x87 Status Register
        "fstat": RegisterDef(name="fstat", size=2),
        # x87 Tag Register
        "ftag": RegisterDef(name="ftag", size=2),
        # x87 Last Instruction Register
        "fip": RegisterDef(name="fip", size=8),
        # x87 Last Operand Pointer
        "fdp": RegisterDef(name="fdp", size=8),
        # x87 Last Opcode
        "fop": RegisterDef(name="fop", size=2),
        # NOTE: Docs disagree on the format of fip and fdp.
        # One source describes them as 48-bit offset-plus-segment,
        # the other describes them as 64-bit.
        # There may also be separate segment registers.
        # If you care about the x87 debug info, please feel free to update.
        # *** MMX Registers ***
        # NOTE: The MMX registers are aliases for the low 8 bytes of the x87 registers.
        # The two subsystems cannot be used simultaneously.
        "mm0": RegisterAliasDef(name="mm0", parent="fpr0", size=8, offset=0),
        "mm1": RegisterAliasDef(name="mm1", parent="fpr1", size=8, offset=0),
        "mm2": RegisterAliasDef(name="mm2", parent="fpr2", size=8, offset=0),
        "mm3": RegisterAliasDef(name="mm3", parent="fpr3", size=8, offset=0),
        "mm4": RegisterAliasDef(name="mm4", parent="fpr4", size=8, offset=0),
        "mm5": RegisterAliasDef(name="mm5", parent="fpr5", size=8, offset=0),
        "mm6": RegisterAliasDef(name="mm6", parent="fpr6", size=8, offset=0),
        "mm7": RegisterAliasDef(name="mm7", parent="fpr7", size=8, offset=0),
        # *** SSE Registers ***
        "xmm0": RegisterDef(name="xmm0", size=16),
        "xmm1": RegisterDef(name="xmm1", size=16),
        "xmm2": RegisterDef(name="xmm2", size=16),
        "xmm3": RegisterDef(name="xmm3", size=16),
        "xmm4": RegisterDef(name="xmm4", size=16),
        "xmm5": RegisterDef(name="xmm5", size=16),
        "xmm6": RegisterDef(name="xmm6", size=16),
        "xmm7": RegisterDef(name="xmm7", size=16),
    }
