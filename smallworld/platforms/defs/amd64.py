import capstone

from ..platforms import Architecture, Byteorder
from .platformdef import PlatformDef, RegisterAliasDef, RegisterDef


class AMD64BasePlatformDef(PlatformDef):
    # Abstract platform def for AMD64
    #
    # AVX512 changes how the xmm and ymm registers are aliased.
    # The new bases are incompatible, so we need two separate classes.
    byteorder = Byteorder.LITTLE

    address_size = 8

    capstone_arch = capstone.CS_ARCH_X86
    capstone_mode = capstone.CS_MODE_64

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

    pc_register = "rip"

    # NOTE: rbp and rsp are not considered general.
    # You _can_ use them as GPRs; it's very rarely a good idea.
    general_purpose_registers = [
        "rax",
        "rbx",
        "rcx",
        "rdx",
        "rdi",
        "rsi",
        "r8",
        "r9",
        "r10",
        "r11",
        "r12",
        "r13",
        "r14",
        "r15",
    ]
    registers = {
        # *** General Purpose Registers ***
        "rax": RegisterDef(name="rax", size=8),
        "eax": RegisterAliasDef(name="eax", parent="rax", size=4, offset=0),
        "ax": RegisterAliasDef(name="ax", parent="rax", size=2, offset=0),
        "al": RegisterAliasDef(name="al", parent="rax", size=1, offset=0),
        "ah": RegisterAliasDef(name="ah", parent="rax", size=1, offset=1),
        "rbx": RegisterDef(name="rbx", size=8),
        "ebx": RegisterAliasDef(name="ebx", parent="rbx", size=4, offset=0),
        "bx": RegisterAliasDef(name="bx", parent="rbx", size=2, offset=0),
        "bl": RegisterAliasDef(name="bl", parent="rbx", size=1, offset=0),
        "bh": RegisterAliasDef(name="bh", parent="rbx", size=1, offset=1),
        "rcx": RegisterDef(name="rcx", size=8),
        "ecx": RegisterAliasDef(name="ecx", parent="rcx", size=4, offset=0),
        "cx": RegisterAliasDef(name="cx", parent="rcx", size=2, offset=0),
        "cl": RegisterAliasDef(name="cl", parent="rcx", size=1, offset=0),
        "ch": RegisterAliasDef(name="ch", parent="rcx", size=1, offset=1),
        "rdx": RegisterDef(name="rdx", size=8),
        "edx": RegisterAliasDef(name="edx", parent="rdx", size=4, offset=0),
        "dx": RegisterAliasDef(name="dx", parent="rdx", size=2, offset=0),
        "dl": RegisterAliasDef(name="dl", parent="rdx", size=1, offset=0),
        "dh": RegisterAliasDef(name="dh", parent="rdx", size=1, offset=1),
        "r8": RegisterDef(name="r8", size=8),
        "r8d": RegisterAliasDef(name="r8d", parent="r8", size=4, offset=0),
        "r8w": RegisterAliasDef(name="r8w", parent="r8", size=2, offset=0),
        "r8b": RegisterAliasDef(name="r8b", parent="r8", size=1, offset=0),
        "r9": RegisterDef(name="r9", size=8),
        "r9d": RegisterAliasDef(name="r9d", parent="r9", size=4, offset=0),
        "r9w": RegisterAliasDef(name="r9w", parent="r9", size=2, offset=0),
        "r9b": RegisterAliasDef(name="r9b", parent="r9", size=1, offset=0),
        "r10": RegisterDef(name="r10", size=8),
        "r10d": RegisterAliasDef(name="r10d", parent="r10", size=4, offset=0),
        "r10w": RegisterAliasDef(name="r10w", parent="r10", size=2, offset=0),
        "r10b": RegisterAliasDef(name="r10b", parent="r10", size=1, offset=0),
        "r11": RegisterDef(name="r11", size=8),
        "r11d": RegisterAliasDef(name="r11d", parent="r11", size=4, offset=0),
        "r11w": RegisterAliasDef(name="r11w", parent="r11", size=2, offset=0),
        "r11b": RegisterAliasDef(name="r11b", parent="r11", size=1, offset=0),
        "r12": RegisterDef(name="r12", size=8),
        "r12d": RegisterAliasDef(name="r12d", parent="r12", size=4, offset=0),
        "r12w": RegisterAliasDef(name="r12w", parent="r12", size=2, offset=0),
        "r12b": RegisterAliasDef(name="r12b", parent="r12", size=1, offset=0),
        "r13": RegisterDef(name="r13", size=8),
        "r13d": RegisterAliasDef(name="r13d", parent="r13", size=4, offset=0),
        "r13w": RegisterAliasDef(name="r13w", parent="r13", size=2, offset=0),
        "r13b": RegisterAliasDef(name="r13b", parent="r13", size=1, offset=0),
        "r14": RegisterDef(name="r14", size=8),
        "r14d": RegisterAliasDef(name="r14d", parent="r14", size=4, offset=0),
        "r14w": RegisterAliasDef(name="r14w", parent="r14", size=2, offset=0),
        "r14b": RegisterAliasDef(name="r14b", parent="r14", size=1, offset=0),
        "r15": RegisterDef(name="r15", size=8),
        "r15d": RegisterAliasDef(name="r15d", parent="r15", size=4, offset=0),
        "r15w": RegisterAliasDef(name="r15w", parent="r15", size=2, offset=0),
        "r15b": RegisterAliasDef(name="r15b", parent="r15", size=1, offset=0),
        "rdi": RegisterDef(name="rdi", size=8),
        "edi": RegisterAliasDef(name="edi", parent="rdi", size=4, offset=0),
        "di": RegisterAliasDef(name="di", parent="rdi", size=2, offset=0),
        "dil": RegisterAliasDef(name="dil", parent="rdi", size=1, offset=0),
        "rsi": RegisterDef(name="rsi", size=8),
        "esi": RegisterAliasDef(name="esi", parent="rsi", size=4, offset=0),
        "si": RegisterAliasDef(name="si", parent="rsi", size=2, offset=0),
        "sil": RegisterAliasDef(name="sil", parent="rsi", size=1, offset=0),
        "rsp": RegisterDef(name="rsp", size=8),
        "esp": RegisterAliasDef(name="esp", parent="rsp", size=4, offset=0),
        "sp": RegisterAliasDef(name="sp", parent="rsp", size=2, offset=0),
        "spl": RegisterAliasDef(name="spl", parent="rsp", size=1, offset=0),
        "rbp": RegisterDef(name="rbp", size=8),
        "ebp": RegisterAliasDef(name="ebp", parent="rbp", size=4, offset=0),
        "bp": RegisterAliasDef(name="bp", parent="rbp", size=2, offset=0),
        "bpl": RegisterAliasDef(name="bpl", parent="rbp", size=1, offset=0),
        # *** Instruction Pointer ***
        "rip": RegisterDef(name="rip", size=8),
        "eip": RegisterAliasDef(name="eip", parent="rip", size=4, offset=0),
        "ip": RegisterAliasDef(name="ip", parent="rip", size=2, offset=0),
        "pc": RegisterAliasDef(name="pc", parent="rip", size=8, offset=0),
        # *** Flags register ***
        "rflags": RegisterDef(name="rflags", size=8),
        "eflags": RegisterAliasDef(name="eflags", parent="rflags", size=4, offset=0),
        "flags": RegisterAliasDef(name="flags", parent="rflags", size=2, offset=0),
        # *** Segment Registers ***
        # NOTE: These are actually 16 bits
        # However, their representation in different emulators gets weird.
        "cs": RegisterDef(name="cs", size=8),
        "ds": RegisterDef(name="ds", size=8),
        "es": RegisterDef(name="es", size=8),
        "fs": RegisterDef(name="fs", size=8),
        "gs": RegisterDef(name="gs", size=8),
        "ss": RegisterDef(name="ss", size=8),
        # *** Control Registers ***
        "cr0": RegisterDef(name="cr0", size=8),
        "cr1": RegisterDef(name="cr1", size=8),
        "cr2": RegisterDef(name="cr2", size=8),
        "cr3": RegisterDef(name="cr3", size=8),
        "cr4": RegisterDef(name="cr4", size=8),
        "cr8": RegisterDef(name="cr8", size=8),
        # *** Debug Registers ***
        "dr0": RegisterDef(name="dr0", size=8),
        "dr1": RegisterDef(name="dr1", size=8),
        "dr2": RegisterDef(name="dr2", size=8),
        "dr3": RegisterDef(name="dr3", size=8),
        "dr6": RegisterDef(name="dr6", size=8),
        "dr7": RegisterDef(name="dr7", size=8),
        "dr8": RegisterDef(name="dr8", size=8),
        "dr9": RegisterDef(name="dr9", size=8),
        "dr10": RegisterDef(name="dr10", size=8),
        "dr11": RegisterDef(name="dr11", size=8),
        "dr12": RegisterDef(name="dr12", size=8),
        "dr13": RegisterDef(name="dr13", size=8),
        "dr14": RegisterDef(name="dr14", size=8),
        "dr15": RegisterDef(name="dr15", size=8),
        # *** Descriptor Table Registers ***
        "gdtr": RegisterDef(name="gdtr", size=10),
        "idtr": RegisterDef(name="idtr", size=10),
        "ldtr": RegisterDef(name="ldtr", size=10),
        # *** Task Register ***
        "tr": RegisterDef(name="tr", size=2),
        # *** x87 registers ***
        # NOTE: These represent the physical registers.
        # x87 references registers as a stack,
        # which isn't possible to represent statically.
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
    }


class AMD64(AMD64BasePlatformDef):
    architecture = Architecture.X86_64

    registers = AMD64BasePlatformDef.registers | {
        # *** SSE/AVX/AVX2 registers ***
        "ymm0": RegisterDef(name="ymm0", size=32),
        "xmm0": RegisterAliasDef(name="xmm0", parent="ymm0", size=16, offset=0),
        "ymm1": RegisterDef(name="ymm1", size=32),
        "xmm1": RegisterAliasDef(name="xmm1", parent="ymm1", size=16, offset=0),
        "ymm2": RegisterDef(name="ymm2", size=32),
        "xmm2": RegisterAliasDef(name="xmm2", parent="ymm2", size=16, offset=0),
        "ymm3": RegisterDef(name="ymm3", size=32),
        "xmm3": RegisterAliasDef(name="xmm3", parent="ymm3", size=16, offset=0),
        "ymm4": RegisterDef(name="ymm4", size=32),
        "xmm4": RegisterAliasDef(name="xmm4", parent="ymm4", size=16, offset=0),
        "ymm5": RegisterDef(name="ymm5", size=32),
        "xmm5": RegisterAliasDef(name="xmm5", parent="ymm5", size=16, offset=0),
        "ymm6": RegisterDef(name="ymm6", size=32),
        "xmm6": RegisterAliasDef(name="xmm6", parent="ymm6", size=16, offset=0),
        "ymm7": RegisterDef(name="ymm7", size=32),
        "xmm7": RegisterAliasDef(name="xmm7", parent="ymm7", size=16, offset=0),
        "ymm8": RegisterDef(name="ymm8", size=32),
        "xmm8": RegisterAliasDef(name="xmm8", parent="ymm8", size=16, offset=0),
        "ymm9": RegisterDef(name="ymm9", size=32),
        "xmm9": RegisterAliasDef(name="xmm9", parent="ymm9", size=16, offset=0),
        "ymm10": RegisterDef(name="ymm10", size=32),
        "xmm10": RegisterAliasDef(name="xmm10", parent="ymm10", size=16, offset=0),
        "ymm11": RegisterDef(name="ymm11", size=32),
        "xmm11": RegisterAliasDef(name="xmm11", parent="ymm11", size=16, offset=0),
        "ymm12": RegisterDef(name="ymm12", size=32),
        "xmm12": RegisterAliasDef(name="xmm12", parent="ymm12", size=16, offset=0),
        "ymm13": RegisterDef(name="ymm13", size=32),
        "xmm13": RegisterAliasDef(name="xmm13", parent="ymm13", size=16, offset=0),
        "ymm14": RegisterDef(name="ymm14", size=32),
        "xmm14": RegisterAliasDef(name="xmm14", parent="ymm14", size=16, offset=0),
        "ymm15": RegisterDef(name="ymm15", size=32),
        "xmm15": RegisterAliasDef(name="xmm15", parent="ymm15", size=16, offset=0),
    }


class AMD64AVX512(AMD64BasePlatformDef):
    architecture = Architecture.X86_64_AVX512

    registers = AMD64BasePlatformDef.registers | {
        # *** SSE/AVX/AVX2/AVX512 registers ***
        "zmm0": RegisterDef(name="zmm0", size=64),
        "ymm0": RegisterAliasDef(name="ymm0", parent="zmm0", size=32, offset=0),
        "xmm0": RegisterAliasDef(name="xmm0", parent="zmm0", size=16, offset=0),
        "zmm1": RegisterDef(name="zmm1", size=64),
        "ymm1": RegisterAliasDef(name="ymm1", parent="zmm1", size=32, offset=0),
        "xmm1": RegisterAliasDef(name="xmm1", parent="zmm1", size=16, offset=0),
        "zmm2": RegisterDef(name="zmm2", size=64),
        "ymm2": RegisterAliasDef(name="ymm2", parent="zmm2", size=32, offset=0),
        "xmm2": RegisterAliasDef(name="xmm2", parent="zmm2", size=16, offset=0),
        "zmm3": RegisterDef(name="zmm3", size=64),
        "ymm3": RegisterAliasDef(name="ymm3", parent="zmm3", size=32, offset=0),
        "xmm3": RegisterAliasDef(name="xmm3", parent="zmm3", size=16, offset=0),
        "zmm4": RegisterDef(name="zmm4", size=64),
        "ymm4": RegisterAliasDef(name="ymm4", parent="zmm4", size=32, offset=0),
        "xmm4": RegisterAliasDef(name="xmm4", parent="zmm4", size=16, offset=0),
        "zmm5": RegisterDef(name="zmm5", size=64),
        "ymm5": RegisterAliasDef(name="ymm5", parent="zmm5", size=32, offset=0),
        "xmm5": RegisterAliasDef(name="xmm5", parent="zmm5", size=16, offset=0),
        "zmm6": RegisterDef(name="zmm6", size=64),
        "ymm6": RegisterAliasDef(name="ymm6", parent="zmm6", size=32, offset=0),
        "xmm6": RegisterAliasDef(name="xmm6", parent="zmm6", size=16, offset=0),
        "zmm7": RegisterDef(name="zmm7", size=64),
        "ymm7": RegisterAliasDef(name="ymm7", parent="zmm7", size=32, offset=0),
        "xmm7": RegisterAliasDef(name="xmm7", parent="zmm7", size=16, offset=0),
        "zmm8": RegisterDef(name="zmm8", size=64),
        "ymm8": RegisterAliasDef(name="ymm8", parent="zmm8", size=32, offset=0),
        "xmm8": RegisterAliasDef(name="xmm8", parent="zmm8", size=16, offset=0),
        "zmm9": RegisterDef(name="zmm9", size=64),
        "ymm9": RegisterAliasDef(name="ymm9", parent="zmm9", size=32, offset=0),
        "xmm9": RegisterAliasDef(name="xmm9", parent="zmm9", size=16, offset=0),
        "zmm10": RegisterDef(name="zmm10", size=64),
        "ymm10": RegisterAliasDef(name="ymm10", parent="zmm10", size=32, offset=0),
        "xmm10": RegisterAliasDef(name="xmm10", parent="zmm10", size=16, offset=0),
        "zmm11": RegisterDef(name="zmm11", size=64),
        "ymm11": RegisterAliasDef(name="ymm11", parent="zmm11", size=32, offset=0),
        "xmm11": RegisterAliasDef(name="xmm11", parent="zmm11", size=16, offset=0),
        "zmm12": RegisterDef(name="zmm12", size=64),
        "ymm12": RegisterAliasDef(name="ymm12", parent="zmm12", size=32, offset=0),
        "xmm12": RegisterAliasDef(name="xmm12", parent="zmm12", size=16, offset=0),
        "zmm13": RegisterDef(name="zmm13", size=64),
        "ymm13": RegisterAliasDef(name="ymm13", parent="zmm13", size=32, offset=0),
        "xmm13": RegisterAliasDef(name="xmm13", parent="zmm13", size=16, offset=0),
        "zmm14": RegisterDef(name="zmm14", size=64),
        "ymm14": RegisterAliasDef(name="ymm14", parent="zmm14", size=32, offset=0),
        "xmm14": RegisterAliasDef(name="xmm14", parent="zmm14", size=16, offset=0),
        "zmm15": RegisterDef(name="zmm15", size=64),
        "ymm15": RegisterAliasDef(name="ymm15", parent="zmm15", size=32, offset=0),
        "xmm15": RegisterAliasDef(name="xmm15", parent="zmm15", size=16, offset=0),
        "zmm16": RegisterDef(name="zmm16", size=64),
        "ymm16": RegisterAliasDef(name="ymm16", parent="zmm16", size=32, offset=0),
        "xmm16": RegisterAliasDef(name="xmm16", parent="zmm16", size=16, offset=0),
        "zmm17": RegisterDef(name="zmm17", size=64),
        "ymm17": RegisterAliasDef(name="ymm17", parent="zmm17", size=32, offset=0),
        "xmm17": RegisterAliasDef(name="xmm17", parent="zmm17", size=16, offset=0),
        "zmm18": RegisterDef(name="zmm18", size=64),
        "ymm18": RegisterAliasDef(name="ymm18", parent="zmm18", size=32, offset=0),
        "xmm18": RegisterAliasDef(name="xmm18", parent="zmm18", size=16, offset=0),
        "zmm19": RegisterDef(name="zmm19", size=64),
        "ymm19": RegisterAliasDef(name="ymm19", parent="zmm19", size=32, offset=0),
        "xmm19": RegisterAliasDef(name="xmm19", parent="zmm19", size=16, offset=0),
        "zmm20": RegisterDef(name="zmm20", size=64),
        "ymm20": RegisterAliasDef(name="ymm20", parent="zmm20", size=32, offset=0),
        "xmm20": RegisterAliasDef(name="xmm20", parent="zmm20", size=16, offset=0),
        "zmm21": RegisterDef(name="zmm21", size=64),
        "ymm21": RegisterAliasDef(name="ymm21", parent="zmm21", size=32, offset=0),
        "xmm21": RegisterAliasDef(name="xmm21", parent="zmm21", size=16, offset=0),
        "zmm22": RegisterDef(name="zmm22", size=64),
        "ymm22": RegisterAliasDef(name="ymm22", parent="zmm22", size=32, offset=0),
        "xmm22": RegisterAliasDef(name="xmm22", parent="zmm22", size=16, offset=0),
        "zmm23": RegisterDef(name="zmm23", size=64),
        "ymm23": RegisterAliasDef(name="ymm23", parent="zmm23", size=32, offset=0),
        "xmm23": RegisterAliasDef(name="xmm23", parent="zmm23", size=16, offset=0),
        "zmm24": RegisterDef(name="zmm24", size=64),
        "ymm24": RegisterAliasDef(name="ymm24", parent="zmm24", size=32, offset=0),
        "xmm24": RegisterAliasDef(name="xmm24", parent="zmm24", size=16, offset=0),
        "zmm25": RegisterDef(name="zmm25", size=64),
        "ymm25": RegisterAliasDef(name="ymm25", parent="zmm25", size=32, offset=0),
        "xmm25": RegisterAliasDef(name="xmm25", parent="zmm25", size=16, offset=0),
        "zmm26": RegisterDef(name="zmm26", size=64),
        "ymm26": RegisterAliasDef(name="ymm26", parent="zmm26", size=32, offset=0),
        "xmm26": RegisterAliasDef(name="xmm26", parent="zmm26", size=16, offset=0),
        "zmm27": RegisterDef(name="zmm27", size=64),
        "ymm27": RegisterAliasDef(name="ymm27", parent="zmm27", size=32, offset=0),
        "xmm27": RegisterAliasDef(name="xmm27", parent="zmm27", size=16, offset=0),
        "zmm28": RegisterDef(name="zmm28", size=64),
        "ymm28": RegisterAliasDef(name="ymm28", parent="zmm28", size=32, offset=0),
        "xmm28": RegisterAliasDef(name="xmm28", parent="zmm28", size=16, offset=0),
        "zmm29": RegisterDef(name="zmm29", size=64),
        "ymm29": RegisterAliasDef(name="ymm29", parent="zmm29", size=32, offset=0),
        "xmm29": RegisterAliasDef(name="xmm29", parent="zmm29", size=16, offset=0),
        "zmm30": RegisterDef(name="zmm30", size=64),
        "ymm30": RegisterAliasDef(name="ymm30", parent="zmm30", size=32, offset=0),
        "xmm30": RegisterAliasDef(name="xmm30", parent="zmm30", size=16, offset=0),
        "zmm31": RegisterDef(name="zmm31", size=64),
        "ymm31": RegisterAliasDef(name="ymm31", parent="zmm31", size=32, offset=0),
        "xmm31": RegisterAliasDef(name="xmm31", parent="zmm31", size=16, offset=0),
    }
