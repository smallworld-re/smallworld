from ..... import platforms
from .....exceptions import ConfigurationError
from ..structs import ElfRela
from .rela import ElfRelocator

# ABI shorthand used in the comments below:
#   A: addend
#   B: base address where the image was loaded
#   GOT: base address of the GOT
#   GOT(S): address of the symbol's GOT entry
#   P: address of the relocation field being updated
#   Pa: P rounded down to a 4-byte boundary
#   S: resolved symbol value
#   T: Thumb-state bit for function symbols
R_ARM_NONE = 0  # No relocation; this entry is a marker only.
R_ARM_PC24 = 1  # Deprecated Arm-state 24-bit branch/call relocation.
R_ARM_ABS32 = 2  # Write (S + A) | T as a 32-bit absolute value.
R_ARM_REL32 = 3  # Write ((S + A) | T) - P as a 32-bit PC-relative value.
R_ARM_LDR_PC_G0 = 4  # Encode S + A - P in an Arm LDR/STR immediate field.
R_ARM_PC13 = R_ARM_LDR_PC_G0  # Legacy elf.h name for R_ARM_LDR_PC_G0.
R_ARM_ABS16 = 5  # Write S + A as a 16-bit absolute value.
R_ARM_ABS12 = 6  # Encode S + A in an Arm LDR/STR immediate field.
R_ARM_THM_ABS5 = 7  # Encode S + A in a Thumb-16 load/store immediate field.
R_ARM_ABS8 = 8  # Write S + A as an 8-bit absolute value.
R_ARM_SBREL32 = 9  # Write ((S + A) | T) - B as a 32-bit base-relative value.
R_ARM_THM_CALL = 10  # Encode ((S + A) | T) - P in a Thumb BL immediate.
R_ARM_THM_PC22 = R_ARM_THM_CALL  # Legacy elf.h name for R_ARM_THM_CALL.
R_ARM_THM_PC8 = 11  # Encode S + A - Pa in a Thumb-16 literal/ADR immediate.
R_ARM_BREL_ADJ = 12  # Dynamic base-adjustment relocation.
R_ARM_AMP_VCALL9 = R_ARM_BREL_ADJ  # Legacy elf.h name for R_ARM_BREL_ADJ.
R_ARM_TLS_DESC = 13  # Dynamic TLS descriptor relocation.
R_ARM_SWI24 = R_ARM_TLS_DESC  # Reused legacy relocation code.
R_ARM_THM_SWI8 = 14  # Obsolete/reserved relocation code.
R_ARM_XPC25 = 15  # Obsolete/reserved relocation code.
R_ARM_THM_XPC22 = 16  # Obsolete/reserved relocation code.
R_ARM_TLS_DTPMOD32 = 17  # Write the TLS module ID containing the symbol.
R_ARM_TLS_DTPOFF32 = 18  # Write the symbol's offset within its TLS block.
R_ARM_TLS_TPOFF32 = 19  # Write the symbol's thread-pointer-relative TLS offset.
R_ARM_COPY = 20  # Copy the symbol's runtime data bytes into the relocation target.
R_ARM_GLOB_DAT = 21  # Populate a GOT slot with (S + A) | T.
R_ARM_JUMP_SLOT = 22  # Populate a PLT/GOT resolver slot with (S + A) | T.
R_ARM_RELATIVE = 23  # Write B + A; ignores the symbol value.
R_ARM_GOTOFF32 = 24  # Write ((S + A) | T) - GOT as a 32-bit GOT-relative value.
R_ARM_GOTOFF = R_ARM_GOTOFF32  # Legacy elf.h name for R_ARM_GOTOFF32.
R_ARM_BASE_PREL = 25  # Write B + A - P as a 32-bit base-relative PC offset.
R_ARM_GOTPC = R_ARM_BASE_PREL  # Legacy elf.h name for R_ARM_BASE_PREL.
R_ARM_GOT_BREL = 26  # Write GOT(S) + A - GOT as a 32-bit GOT-entry-relative value.
R_ARM_GOT32 = R_ARM_GOT_BREL  # Legacy elf.h name for R_ARM_GOT_BREL.
R_ARM_PLT32 = 27  # Deprecated Arm-state 24-bit PLT-relative branch relocation.
R_ARM_CALL = 28  # Encode ((S + A) | T) - P in an Arm BL/BLX immediate.
R_ARM_JUMP24 = 29  # Encode ((S + A) | T) - P in an Arm B/BL<cond> immediate.
R_ARM_THM_JUMP24 = 30  # Encode ((S + A) | T) - P in a Thumb B.W immediate.
R_ARM_BASE_ABS = 31  # Write B + A as a 32-bit base-relative absolute value.
R_ARM_ALU_PCREL_7_0 = 32  # Obsolete Arm ADD/SUB PC-relative low-group relocation.
R_ARM_ALU_PCREL_15_8 = 33  # Obsolete Arm ADD/SUB PC-relative middle-group relocation.
R_ARM_ALU_PCREL_23_15 = 34  # Obsolete Arm ADD/SUB PC-relative high-group relocation.
R_ARM_LDR_SBREL_11_0_NC = (
    35  # Deprecated Arm base-relative load/store low-group relocation.
)
R_ARM_LDR_SBREL_11_0 = R_ARM_LDR_SBREL_11_0_NC  # Legacy elf.h name.
R_ARM_ALU_SBREL_19_12_NC = 36  # Deprecated Arm base-relative middle-group relocation.
R_ARM_ALU_SBREL_19_12 = R_ARM_ALU_SBREL_19_12_NC  # Legacy elf.h name.
R_ARM_ALU_SBREL_27_20_CK = 37  # Deprecated Arm base-relative high-group relocation.
R_ARM_ALU_SBREL_27_20 = R_ARM_ALU_SBREL_27_20_CK  # Legacy elf.h name.
R_ARM_TARGET1 = 38  # Platform-defined ABS32 or REL32 relocation.
R_ARM_SBREL31 = 39  # Deprecated 31-bit base-relative data relocation.
R_ARM_V4BX = 40  # Armv4BX compatibility marker relocation.
R_ARM_TARGET2 = 41  # Platform-defined runtime-support relocation.
R_ARM_PREL31 = 42  # Write ((S + A) | T) - P in the low 31 bits of the word.
R_ARM_MOVW_ABS_NC = 43  # Encode (S + A) | T in an Arm MOVW immediate.
R_ARM_MOVT_ABS = 44  # Encode S + A in an Arm MOVT immediate.
R_ARM_MOVW_PREL_NC = 45  # Encode ((S + A) | T) - P in an Arm MOVW immediate.
R_ARM_MOVT_PREL = 46  # Encode S + A - P in an Arm MOVT immediate.
R_ARM_THM_MOVW_ABS_NC = 47  # Encode (S + A) | T in a Thumb MOVW immediate.
R_ARM_THM_MOVT_ABS = 48  # Encode S + A in a Thumb MOVT immediate.
R_ARM_THM_MOVW_PREL_NC = 49  # Encode ((S + A) | T) - P in a Thumb MOVW immediate.
R_ARM_THM_MOVT_PREL = 50  # Encode S + A - P in a Thumb MOVT immediate.
R_ARM_THM_JUMP19 = 51  # Encode ((S + A) | T) - P in a Thumb conditional B.W immediate.
R_ARM_THM_JUMP6 = 52  # Encode S + A - P in a Thumb CBZ/CBNZ immediate.
R_ARM_THM_ALU_PREL_11_0 = 53  # Encode ((S + A) | T) - Pa in a Thumb ADR.W immediate.
R_ARM_THM_PC12 = 54  # Encode S + A - Pa in a Thumb literal LDR immediate.
R_ARM_ABS32_NOI = 55  # Write S + A as a 32-bit absolute value, ignoring T.
R_ARM_REL32_NOI = 56  # Write S + A - P as a 32-bit PC-relative value, ignoring T.
R_ARM_ALU_PC_G0_NC = 57  # Encode the first unchecked Arm PC-relative ALU group.
R_ARM_ALU_PC_G0 = 58  # Encode the first checked Arm PC-relative ALU group.
R_ARM_ALU_PC_G1_NC = 59  # Encode the second unchecked Arm PC-relative ALU group.
R_ARM_ALU_PC_G1 = 60  # Encode the second checked Arm PC-relative ALU group.
R_ARM_ALU_PC_G2 = 61  # Encode the third checked Arm PC-relative ALU group.
R_ARM_LDR_PC_G1 = 62  # Encode the second Arm PC-relative load/store group.
R_ARM_LDR_PC_G2 = 63  # Encode the third Arm PC-relative load/store group.
R_ARM_LDRS_PC_G0 = 64  # Encode the first Arm PC-relative halfword/doubleword group.
R_ARM_LDRS_PC_G1 = 65  # Encode the second Arm PC-relative halfword/doubleword group.
R_ARM_LDRS_PC_G2 = 66  # Encode the third Arm PC-relative halfword/doubleword group.
R_ARM_LDC_PC_G0 = 67  # Encode the first Arm PC-relative LDC/STC group.
R_ARM_LDC_PC_G1 = 68  # Encode the second Arm PC-relative LDC/STC group.
R_ARM_LDC_PC_G2 = 69  # Encode the third Arm PC-relative LDC/STC group.
R_ARM_ALU_SB_G0_NC = 70  # Encode the first unchecked Arm base-relative ALU group.
R_ARM_ALU_SB_G0 = 71  # Encode the first checked Arm base-relative ALU group.
R_ARM_ALU_SB_G1_NC = 72  # Encode the second unchecked Arm base-relative ALU group.
R_ARM_ALU_SB_G1 = 73  # Encode the second checked Arm base-relative ALU group.
R_ARM_ALU_SB_G2 = 74  # Encode the third checked Arm base-relative ALU group.
R_ARM_LDR_SB_G0 = 75  # Encode the first Arm base-relative load/store group.
R_ARM_LDR_SB_G1 = 76  # Encode the second Arm base-relative load/store group.
R_ARM_LDR_SB_G2 = 77  # Encode the third Arm base-relative load/store group.
R_ARM_LDRS_SB_G0 = 78  # Encode the first Arm base-relative halfword/doubleword group.
R_ARM_LDRS_SB_G1 = 79  # Encode the second Arm base-relative halfword/doubleword group.
R_ARM_LDRS_SB_G2 = 80  # Encode the third Arm base-relative halfword/doubleword group.
R_ARM_LDC_SB_G0 = 81  # Encode the first Arm base-relative LDC/STC group.
R_ARM_LDC_SB_G1 = 82  # Encode the second Arm base-relative LDC/STC group.
R_ARM_LDC_SB_G2 = 83  # Encode the third Arm base-relative LDC/STC group.
R_ARM_MOVW_BREL_NC = 84  # Encode ((S + A) | T) - B in an Arm MOVW immediate.
R_ARM_MOVT_BREL = 85  # Encode S + A - B in an Arm MOVT immediate.
R_ARM_MOVW_BREL = 86  # Encode a checked ((S + A) | T) - B in an Arm MOVW immediate.
R_ARM_THM_MOVW_BREL_NC = 87  # Encode ((S + A) | T) - B in a Thumb MOVW immediate.
R_ARM_THM_MOVT_BREL = 88  # Encode S + A - B in a Thumb MOVT immediate.
R_ARM_THM_MOVW_BREL = (
    89  # Encode a checked ((S + A) | T) - B in a Thumb MOVW immediate.
)
R_ARM_TLS_GOTDESC = 90  # Experimental static TLSDESC GOT-entry relocation.
R_ARM_TLS_CALL = 91  # Experimental static TLSDESC call marker.
R_ARM_TLS_DESCSEQ = 92  # Experimental static TLSDESC relaxation marker.
R_ARM_THM_TLS_CALL = 93  # Experimental Thumb TLSDESC call marker.
R_ARM_PLT32_ABS = 94  # Write PLT(S) + A as a 32-bit absolute value.
R_ARM_GOT_ABS = 95  # Write GOT(S) + A as a 32-bit absolute value.
R_ARM_GOT_PREL = 96  # Write GOT(S) + A - P as a 32-bit PC-relative value.
R_ARM_GOT_BREL12 = 97  # Encode GOT(S) + A - GOT in an Arm LDR immediate.
R_ARM_GOTOFF12 = 98  # Encode S + A - GOT in an Arm LDR/STR immediate.
R_ARM_GOTRELAX = 99  # Reserved GOT-relaxation marker relocation.
R_ARM_GNU_VTENTRY = 100  # Deprecated virtual-table optimization marker.
R_ARM_GNU_VTINHERIT = 101  # Deprecated virtual-table inheritance marker.
R_ARM_THM_JUMP11 = 102  # Encode S + A - P in a Thumb-16 unconditional branch.
R_ARM_THM_PC11 = R_ARM_THM_JUMP11  # Legacy elf.h name for R_ARM_THM_JUMP11.
R_ARM_THM_JUMP8 = 103  # Encode S + A - P in a Thumb-16 conditional branch.
R_ARM_THM_PC9 = R_ARM_THM_JUMP8  # Legacy elf.h name for R_ARM_THM_JUMP8.
R_ARM_TLS_GD32 = 104  # Write the TLS GD GOT-pair address relative to P.
R_ARM_TLS_LDM32 = 105  # Write the TLS LD GOT-pair address relative to P.
R_ARM_TLS_LDO32 = 106  # Write S + A - TLS as a 32-bit TLS-block-relative value.
R_ARM_TLS_IE32 = 107  # Write the TLS IE GOT-entry address relative to P.
R_ARM_TLS_LE32 = 108  # Write S + A - tp as a 32-bit thread-pointer-relative value.
R_ARM_TLS_LDO12 = 109  # Encode S + A - TLS in an Arm LDR/STR immediate.
R_ARM_TLS_LE12 = 110  # Encode S + A - tp in an Arm LDR/STR immediate.
R_ARM_TLS_IE12GP = 111  # Encode the TLS IE GOT-entry address relative to GOT.
R_ARM_PRIVATE_0_LO = 112  # Start of the first private relocation range.
R_ARM_PRIVATE_0_HI = 127  # End of the first private relocation range.
R_ARM_ME_TOO = 128  # Obsolete relocation code.
R_ARM_THM_TLS_DESCSEQ16 = 129  # Experimental Thumb-16 TLSDESC relaxation marker.
R_ARM_THM_TLS_DESCSEQ = R_ARM_THM_TLS_DESCSEQ16  # Legacy elf.h alias.
R_ARM_THM_TLS_DESCSEQ32 = 130  # Experimental Thumb-32 TLSDESC relaxation marker.
R_ARM_THM_GOT_BREL12 = 131  # Encode GOT(S) + A - GOT in a Thumb LDR immediate.
R_ARM_THM_ALU_ABS_G0_NC = 132  # Encode the low 8 bits of (S + A) | T in Thumb-16.
R_ARM_THM_ALU_ABS_G1_NC = 133  # Encode bits [15:8] of S + A in Thumb-16.
R_ARM_THM_ALU_ABS_G2_NC = 134  # Encode bits [23:16] of S + A in Thumb-16.
R_ARM_THM_ALU_ABS_G3 = 135  # Encode bits [31:24] of S + A in Thumb-16.
R_ARM_THM_BF16 = 136  # Encode ((S + A) | T) - P in a Thumb BF16 immediate.
R_ARM_THM_BF12 = 137  # Encode ((S + A) | T) - P in a Thumb BF12 immediate.
R_ARM_THM_BF18 = 138  # Encode ((S + A) | T) - P in a Thumb BF18 immediate.
R_ARM_RESERVED_0_LO = 139  # Start of the first unallocated standard range.
R_ARM_RESERVED_0_HI = 159  # End of the first unallocated standard range.
R_ARM_IRELATIVE = 160  # Write the return value of an IFUNC resolver at B + A.
R_ARM_PRIVATE_1_LO = 161  # Start of the second private relocation range.
R_ARM_PRIVATE_1_HI = 176  # End of the second private relocation range.
R_ARM_RESERVED_1_LO = 177  # Start of the second unallocated standard range.
R_ARM_RESERVED_1_HI = 248  # End of the second unallocated standard range.
R_ARM_RXPC25 = 249  # Legacy non-AAELF ARM relocation; semantics are platform-specific.
R_ARM_RSBREL32 = (
    250  # Legacy non-AAELF ARM relocation; semantics are platform-specific.
)
R_ARM_THM_RPC22 = (
    251  # Legacy non-AAELF ARM relocation; semantics are platform-specific.
)
R_ARM_RREL32 = 252  # Legacy non-AAELF ARM relocation; semantics are platform-specific.
R_ARM_RABS22 = 253  # Legacy non-AAELF ARM relocation; semantics are platform-specific.
R_ARM_RPC24 = 254  # Legacy non-AAELF ARM relocation; semantics are platform-specific.
R_ARM_RBASE = 255  # Legacy non-AAELF ARM relocation; semantics are platform-specific.
R_ARM_NUM = 256  # This and higher are not valid standard ARM relocation codes.

DT_PLTGOT = 3  # Dynamic tag for the GOT base address.
ARM_OPCODE_SUB = 0b0010
ARM_OPCODE_ADD = 0b0100
THUMB_NOP_W = 0xF3AF8000


class ArmElfRelocator(ElfRelocator):
    byteorder = platforms.Byteorder.LITTLE

    def _symbol_name(self, rela: ElfRela) -> str:
        return rela.symbol.name if rela.symbol.name else "<anonymous>"

    def _symbol_value(self, rela: ElfRela) -> int:
        # ARM ELF function symbols conventionally carry the Thumb entry-state bit
        # in bit 0 of st_value. Relocations whose formulas include "| T" use this
        # raw value; the others clear it explicitly.
        return rela.symbol.value + rela.symbol.baseaddr

    def _symbol_addr(self, rela: ElfRela, include_thumb_bit: bool) -> int:
        value = self._symbol_value(rela)
        return value if include_thumb_bit else (value & ~1)

    def _pack(self, value: int, size: int) -> bytes:
        mask = (1 << (size * 8)) - 1
        return (value & mask).to_bytes(size, self.byteorder.value)

    def _pack_thumb16(self, value: int) -> bytes:
        return self._pack(value, 2)

    def _pack_arm32(self, value: int) -> bytes:
        return self._pack(value, 4)

    def _pack_thumb32(self, value: int) -> bytes:
        hw1 = (value >> 16) & 0xFFFF
        hw2 = value & 0xFFFF
        return hw1.to_bytes(2, self.byteorder.value) + hw2.to_bytes(
            2, self.byteorder.value
        )

    def _read_arm32(self, rela: ElfRela, elf) -> int:
        return elf.read_int(rela.offset, 4, self.byteorder)

    def _read_thumb16(self, rela: ElfRela, elf) -> int:
        return elf.read_int(rela.offset, 2, self.byteorder)

    def _read_thumb32(self, rela: ElfRela, elf) -> int:
        hw1 = elf.read_int(rela.offset, 2, self.byteorder)
        hw2 = elf.read_int(rela.offset + 2, 2, self.byteorder)
        return (hw1 << 16) | hw2

    def _sign_extend(self, value: int, bits: int) -> int:
        sign = 1 << (bits - 1)
        return (value & (sign - 1)) - (value & sign)

    def _get_data_addend(self, rela: ElfRela, elf, size: int) -> int:
        if rela.is_rela:
            return rela.addend
        return int.from_bytes(
            elf.read_bytes(rela.offset, size), self.byteorder.value, signed=True
        )

    def _get_arm_branch_addend(self, rela: ElfRela, elf) -> int:
        if rela.is_rela:
            return rela.addend
        orig = self._read_arm32(rela, elf)
        return self._sign_extend((orig & 0x00FFFFFF) << 2, 26)

    def _get_arm_mem12_addend(self, rela: ElfRela, elf) -> int:
        if rela.is_rela:
            return rela.addend
        orig = self._read_arm32(rela, elf)
        imm = orig & 0xFFF
        return imm if (orig >> 23) & 1 else -imm

    def _get_arm_mem8_addend(self, rela: ElfRela, elf) -> int:
        if rela.is_rela:
            return rela.addend
        orig = self._read_arm32(rela, elf)
        imm = ((orig >> 4) & 0xF0) | (orig & 0xF)
        return imm if (orig >> 23) & 1 else -imm

    def _get_arm_ldc_addend(self, rela: ElfRela, elf) -> int:
        if rela.is_rela:
            return rela.addend
        orig = self._read_arm32(rela, elf)
        imm = (orig & 0xFF) << 2
        return imm if (orig >> 23) & 1 else -imm

    def _get_arm_add_sub_addend(self, rela: ElfRela, elf) -> int:
        if rela.is_rela:
            return rela.addend
        orig = self._read_arm32(rela, elf)
        imm = self._decode_arm_imm12(orig & 0xFFF)
        return -imm if ((orig >> 21) & 0xF) == ARM_OPCODE_SUB else imm

    def _get_arm_mov_addend(self, rela: ElfRela, elf) -> int:
        if rela.is_rela:
            return rela.addend
        orig = self._read_arm32(rela, elf)
        imm16 = ((orig >> 16) & 0xF) << 12 | (orig & 0xFFF)
        return self._sign_extend(imm16, 16)

    def _get_thumb_mov_addend(self, rela: ElfRela, elf) -> int:
        if rela.is_rela:
            return rela.addend
        orig = self._read_thumb32(rela, elf)
        imm16 = self._extract_thumb_mov_imm16(orig)
        return self._sign_extend(imm16, 16)

    def _get_thumb_bl_addend(self, rela: ElfRela, elf) -> int:
        if rela.is_rela:
            return rela.addend
        orig = self._read_thumb32(rela, elf)
        s = (orig >> 26) & 1
        j1 = (orig >> 13) & 1
        j2 = (orig >> 11) & 1
        i1 = (~(j1 ^ s)) & 1
        i2 = (~(j2 ^ s)) & 1
        imm10 = (orig >> 16) & 0x3FF
        imm11 = orig & 0x7FF
        value = (s << 24) | (i1 << 23) | (i2 << 22) | (imm10 << 12) | (imm11 << 1)
        return self._sign_extend(value, 25)

    def _get_thumb_jump19_addend(self, rela: ElfRela, elf) -> int:
        if rela.is_rela:
            return rela.addend
        orig = self._read_thumb32(rela, elf)
        s = (orig >> 26) & 1
        j1 = (orig >> 13) & 1
        j2 = (orig >> 11) & 1
        i1 = (~(j1 ^ s)) & 1
        i2 = (~(j2 ^ s)) & 1
        imm6 = (orig >> 16) & 0x3F
        imm11 = orig & 0x7FF
        value = (s << 20) | (i1 << 19) | (i2 << 18) | (imm6 << 12) | (imm11 << 1)
        return self._sign_extend(value, 21)

    def _get_thumb_pc8_addend(self, rela: ElfRela, elf) -> int:
        if rela.is_rela:
            return rela.addend
        orig = self._read_thumb16(rela, elf)
        imm = (orig & 0xFF) << 2
        return ((imm + 4) & 0x3FF) - 4

    def _get_thumb_jump6_addend(self, rela: ElfRela, elf) -> int:
        if rela.is_rela:
            return rela.addend
        orig = self._read_thumb16(rela, elf)
        imm = (((orig >> 9) & 1) << 6) | (((orig >> 3) & 0x1F) << 1)
        return ((imm + 4) & 0x7F) - 4

    def _get_thumb_branch16_addend(self, rela: ElfRela, elf, bits: int) -> int:
        if rela.is_rela:
            return rela.addend
        orig = self._read_thumb16(rela, elf)
        mask = (1 << bits) - 1
        imm = (orig & mask) << 1
        return self._sign_extend(imm, bits + 1)

    def _get_thumb_imm8_addend(self, rela: ElfRela, elf) -> int:
        if rela.is_rela:
            return rela.addend
        return self._read_thumb16(rela, elf) & 0xFF

    def _get_thumb_adr_addend(self, rela: ElfRela, elf) -> int:
        if rela.is_rela:
            return rela.addend
        orig = self._read_thumb32(rela, elf)
        imm = ((orig >> 26) & 1) << 11 | ((orig >> 12) & 0x7) << 8 | (orig & 0xFF)
        return imm if (orig >> 23) & 1 else -imm

    def _get_thumb_mem12_addend(self, rela: ElfRela, elf, signed: bool) -> int:
        if rela.is_rela:
            return rela.addend
        orig = self._read_thumb32(rela, elf)
        imm = orig & 0xFFF
        if not signed:
            return imm
        return imm if (orig >> 23) & 1 else -imm

    def _get_thumb_bf_addend(self, rela: ElfRela, elf, width: int) -> int:
        if rela.is_rela:
            return rela.addend
        orig = self._read_thumb32(rela, elf)
        if rela.type == R_ARM_THM_BF16:
            imm = ((orig >> 16) & 0x1F) << 12 | ((orig >> 1) & 0x3FF) << 2
        elif rela.type == R_ARM_THM_BF12:
            imm = ((orig >> 16) & 0x1) << 12 | ((orig >> 1) & 0x3FF) << 2
        else:
            imm = ((orig >> 16) & 0x7F) << 12 | ((orig >> 1) & 0x3FF) << 2
        imm |= ((orig >> 11) & 1) << 1
        imm |= 1
        return self._sign_extend(imm, width)

    def _check_range(
        self, value: int, lower: int, upper: int, rela: ElfRela, detail: str
    ) -> None:
        if not (lower <= value < upper):
            raise ConfigurationError(
                f"Relocation {hex(rela.type)} for {self._symbol_name(rela)} "
                f"overflowed {detail}: {value}"
            )

    def _check_aligned(
        self, value: int, alignment: int, rela: ElfRela, detail: str
    ) -> None:
        if value % alignment != 0:
            raise ConfigurationError(
                f"Relocation {hex(rela.type)} for {self._symbol_name(rela)} "
                f"requires {detail} aligned to {alignment} bytes, got {value}"
            )

    def _missing_context(self, rela: ElfRela, detail: str) -> None:
        raise ConfigurationError(
            f"Relocation {hex(rela.type)} for {self._symbol_name(rela)} requires "
            f"{detail}, which is not available to ArmElfRelocator._compute_value()"
        )

    def _ror32(self, value: int, amount: int) -> int:
        amount %= 32
        return (
            (value >> amount) | ((value << (32 - amount)) & 0xFFFFFFFF)
        ) & 0xFFFFFFFF

    def _rol32(self, value: int, amount: int) -> int:
        amount %= 32
        return ((value << amount) | (value >> (32 - amount))) & 0xFFFFFFFF

    def _decode_arm_imm12(self, imm12: int) -> int:
        imm8 = imm12 & 0xFF
        rot = ((imm12 >> 8) & 0xF) * 2
        return self._ror32(imm8, rot)

    def _encode_arm_imm12(self, value: int, rela: ElfRela, detail: str) -> int:
        value &= 0xFFFFFFFF
        for rot in range(16):
            imm8 = self._rol32(value, rot * 2) & 0xFF
            if self._ror32(imm8, rot * 2) == value:
                return (rot << 8) | imm8
        raise ConfigurationError(
            f"Relocation {hex(rela.type)} for {self._symbol_name(rela)} cannot "
            f"encode {detail} as an Arm rotated-immediate: {hex(value)}"
        )

    def _arm_group(self, residual: int) -> int:
        if residual == 0:
            return 0
        msb = residual.bit_length() - 1
        for k in range(16):
            if (1 << msb) & (0xFF << (2 * k)):
                return residual & (0xFF << (2 * k))
        return residual & 0xFF

    def _arm_group_value(self, abs_value: int, index: int) -> tuple[int, int]:
        residual = abs_value
        for _ in range(index):
            residual &= ~self._arm_group(residual)
        group = self._arm_group(residual)
        return group, residual & ~group

    def _arm_group_residual(self, abs_value: int, groups_removed: int) -> int:
        residual = abs_value
        for _ in range(groups_removed):
            residual &= ~self._arm_group(residual)
        return residual

    def _patch_arm_branch(self, orig: int, value: int) -> int:
        return (orig & 0xFF000000) | ((value >> 2) & 0x00FFFFFF)

    def _patch_arm_blx(self, value: int) -> int:
        even_value = value & ~1
        imm24 = (even_value >> 2) & 0x00FFFFFF
        h = (even_value >> 1) & 1
        return 0xFA000000 | (h << 24) | imm24

    def _patch_arm_mem12(self, orig: int, value: int) -> int:
        patched = orig & ~((1 << 23) | 0xFFF)
        if value >= 0:
            patched |= 1 << 23
        patched |= abs(value) & 0xFFF
        return patched

    def _patch_arm_mem8_split(self, orig: int, value: int) -> int:
        imm = abs(value) & 0xFF
        patched = orig & ~((1 << 23) | (0xF << 8) | 0xF)
        if value >= 0:
            patched |= 1 << 23
        patched |= ((imm >> 4) & 0xF) << 8
        patched |= imm & 0xF
        return patched

    def _patch_arm_ldc(self, orig: int, value: int) -> int:
        imm = abs(value) >> 2
        patched = orig & ~((1 << 23) | 0xFF)
        if value >= 0:
            patched |= 1 << 23
        patched |= imm & 0xFF
        return patched

    def _patch_arm_add_sub(
        self, orig: int, value: int, rela: ElfRela, detail: str
    ) -> int:
        imm12 = self._encode_arm_imm12(abs(value), rela, detail)
        opcode = ARM_OPCODE_ADD if value >= 0 else ARM_OPCODE_SUB
        return (orig & ~((0xF << 21) | 0xFFF)) | (opcode << 21) | imm12

    def _patch_arm_mov(self, orig: int, imm16: int) -> int:
        return (
            (orig & ~((0xF << 16) | 0xFFF))
            | (((imm16 >> 12) & 0xF) << 16)
            | (imm16 & 0xFFF)
        )

    def _extract_thumb_mov_imm16(self, orig: int) -> int:
        return (
            ((orig >> 16) & 0xF) << 12
            | ((orig >> 26) & 1) << 11
            | ((orig >> 12) & 0x7) << 8
            | (orig & 0xFF)
        )

    def _patch_thumb_mov(self, orig: int, imm16: int) -> int:
        patched = orig
        patched = (patched & ~(0xF << 16)) | (((imm16 >> 12) & 0xF) << 16)
        patched = (patched & ~(1 << 26)) | (((imm16 >> 11) & 1) << 26)
        patched = (patched & ~(0x7 << 12)) | (((imm16 >> 8) & 0x7) << 12)
        patched = (patched & ~0xFF) | (imm16 & 0xFF)
        return patched

    def _patch_thumb_bl(self, orig: int, value: int) -> int:
        s = (value >> 24) & 1
        i1 = (value >> 23) & 1
        i2 = (value >> 22) & 1
        imm10 = (value >> 12) & 0x3FF
        imm11 = (value >> 1) & 0x7FF
        j1 = ((~i1) & 1) ^ s
        j2 = ((~i2) & 1) ^ s
        hw1 = (orig >> 16) & 0xFFFF
        hw2 = orig & 0xFFFF
        hw1 = (hw1 & ~0x7FF) | (s << 10) | imm10
        hw2 = (hw2 & ~((1 << 13) | (1 << 11) | 0x7FF)) | (j1 << 13) | (j2 << 11) | imm11
        return (hw1 << 16) | hw2

    def _patch_thumb_jump19(self, orig: int, value: int) -> int:
        s = (value >> 20) & 1
        i1 = (value >> 19) & 1
        i2 = (value >> 18) & 1
        imm6 = (value >> 12) & 0x3F
        imm11 = (value >> 1) & 0x7FF
        j1 = ((~i1) & 1) ^ s
        j2 = ((~i2) & 1) ^ s
        hw1 = (orig >> 16) & 0xFFFF
        hw2 = orig & 0xFFFF
        hw1 = (hw1 & ~((1 << 10) | 0x3F)) | (s << 10) | imm6
        hw2 = (hw2 & ~((1 << 13) | (1 << 11) | 0x7FF)) | (j1 << 13) | (j2 << 11) | imm11
        return (hw1 << 16) | hw2

    def _patch_thumb_mem12(self, orig: int, value: int, signed: bool) -> int:
        patched = orig & ~((1 << 23) | 0xFFF)
        if signed:
            if value >= 0:
                patched |= 1 << 23
            patched |= abs(value) & 0xFFF
        else:
            patched |= value & 0xFFF
        return patched

    def _patch_thumb_adr(self, orig: int, value: int) -> int:
        patched = self._patch_thumb_mov(orig, abs(value) & 0xFFF)
        patched &= ~(1 << 23)
        if value >= 0:
            patched |= 1 << 23
        return patched

    def _patch_thumb_bf(self, orig: int, value: int, kind: int) -> int:
        patched = orig & ~((0x3FF << 1) | (1 << 11))
        patched |= ((value >> 2) & 0x3FF) << 1
        patched |= ((value >> 1) & 1) << 11
        if kind == R_ARM_THM_BF16:
            patched = (patched & ~(0x1F << 16)) | (((value >> 12) & 0x1F) << 16)
        elif kind == R_ARM_THM_BF12:
            patched = (patched & ~(1 << 16)) | (((value >> 12) & 1) << 16)
        else:
            patched = (patched & ~(0x7F << 16)) | (((value >> 12) & 0x7F) << 16)
        return patched

    def _got_base(self, rela: ElfRela, elf) -> int:
        dtags = getattr(elf, "_dtags", {})
        if DT_PLTGOT in dtags:
            return elf._rebase_file(dtags[DT_PLTGOT])

        lief_elf = getattr(elf, "_elf", None)
        section_offsets = getattr(elf, "_section_offsets", {})
        if lief_elf is not None:
            for name in (".got.plt", ".got"):
                for idx, section in enumerate(lief_elf.sections):
                    if section.name != name:
                        continue
                    if getattr(section, "virtual_address", 0):
                        return elf._rebase_file(section.virtual_address)
                    if idx in section_offsets:
                        return elf.address + section_offsets[idx]

        self._missing_context(rela, "the GOT base address")

    def _proxy_offset(self, rela: ElfRela, proxy_types, detail: str) -> int:
        offsets = sorted({r.offset for r in rela.symbol.relas if r.type in proxy_types})
        if len(offsets) == 1:
            return offsets[0]
        if len(offsets) == 0:
            self._missing_context(rela, detail)
        raise ConfigurationError(
            f"Relocation {hex(rela.type)} for {self._symbol_name(rela)} has "
            f"multiple candidate proxy entries for {detail}: "
            f"{', '.join(map(hex, offsets))}"
        )

    def _tls_pair_base(self, rela: ElfRela, proxy_types, detail: str) -> int:
        offsets = sorted({r.offset for r in rela.symbol.relas if r.type in proxy_types})
        if len(offsets) == 1:
            return offsets[0]
        if len(offsets) == 2 and offsets[1] - offsets[0] == 4:
            return offsets[0]
        if len(offsets) == 0:
            self._missing_context(rela, detail)
        raise ConfigurationError(
            f"Relocation {hex(rela.type)} for {self._symbol_name(rela)} has "
            f"ambiguous TLS proxy entries for {detail}: "
            f"{', '.join(map(hex, offsets))}"
        )

    def _compute_value(self, rela: ElfRela, elf):
        sym_t = self._symbol_addr(rela, include_thumb_bit=True)
        sym = self._symbol_addr(rela, include_thumb_bit=False)
        base = elf.address
        got_base = None

        if rela.type == R_ARM_NONE:
            return b""

        elif rela.type == R_ARM_ABS32:
            return self._pack(sym_t + self._get_data_addend(rela, elf, 4), 4)
        elif rela.type == R_ARM_REL32:
            return self._pack(
                sym_t + self._get_data_addend(rela, elf, 4) - rela.offset, 4
            )
        elif rela.type == R_ARM_ABS16:
            value = sym + self._get_data_addend(rela, elf, 2)
            self._check_range(value, -(1 << 15), 1 << 16, rela, "ABS16")
            return self._pack(value, 2)
        elif rela.type == R_ARM_ABS8:
            value = sym + self._get_data_addend(rela, elf, 1)
            self._check_range(value, -(1 << 7), 1 << 8, rela, "ABS8")
            return self._pack(value, 1)
        elif rela.type == R_ARM_SBREL32:
            return self._pack(sym_t + self._get_data_addend(rela, elf, 4) - base, 4)
        elif rela.type == R_ARM_GLOB_DAT:
            return self._pack(sym_t + self._get_data_addend(rela, elf, 4), 4)
        elif rela.type == R_ARM_JUMP_SLOT:
            return self._pack(sym_t + self._get_data_addend(rela, elf, 4), 4)
        elif rela.type == R_ARM_RELATIVE:
            return self._pack(base + self._get_data_addend(rela, elf, 4), 4)
        elif rela.type == R_ARM_GOTOFF32:
            got_base = self._got_base(rela, elf)
            return self._pack(sym_t + self._get_data_addend(rela, elf, 4) - got_base, 4)
        elif rela.type == R_ARM_BASE_PREL:
            return self._pack(
                base + self._get_data_addend(rela, elf, 4) - rela.offset, 4
            )
        elif rela.type == R_ARM_GOT_BREL:
            got_entry = self._proxy_offset(
                rela,
                (R_ARM_GLOB_DAT, R_ARM_JUMP_SLOT),
                "the symbol's GOT entry address",
            )
            got_base = self._got_base(rela, elf)
            return self._pack(
                got_entry + self._get_data_addend(rela, elf, 4) - got_base, 4
            )
        elif rela.type == R_ARM_BASE_ABS:
            return self._pack(base + self._get_data_addend(rela, elf, 4), 4)
        elif rela.type == R_ARM_ABS32_NOI:
            return self._pack(sym + self._get_data_addend(rela, elf, 4), 4)
        elif rela.type == R_ARM_REL32_NOI:
            return self._pack(
                sym + self._get_data_addend(rela, elf, 4) - rela.offset, 4
            )
        elif rela.type == R_ARM_PREL31:
            addend = (
                rela.addend
                if rela.is_rela
                else self._sign_extend(self._read_arm32(rela, elf) & 0x7FFFFFFF, 31)
            )
            value = sym_t + addend - rela.offset
            self._check_range(value, -(1 << 30), 1 << 30, rela, "PREL31")
            orig = self._read_arm32(rela, elf)
            return self._pack_arm32((orig & 0x80000000) | (value & 0x7FFFFFFF))
        elif rela.type == R_ARM_SBREL31:
            addend = (
                rela.addend
                if rela.is_rela
                else self._sign_extend(self._read_arm32(rela, elf) & 0x7FFFFFFF, 31)
            )
            value = sym_t + addend - base
            self._check_range(value, -(1 << 30), 1 << 30, rela, "SBREL31")
            orig = self._read_arm32(rela, elf)
            return self._pack_arm32((orig & 0x80000000) | (value & 0x7FFFFFFF))
        elif rela.type == R_ARM_GOT_ABS:
            got_entry = self._proxy_offset(
                rela,
                (R_ARM_GLOB_DAT, R_ARM_JUMP_SLOT),
                "the symbol's GOT entry address",
            )
            return self._pack(got_entry + self._get_data_addend(rela, elf, 4), 4)
        elif rela.type == R_ARM_GOT_PREL:
            got_entry = self._proxy_offset(
                rela,
                (R_ARM_GLOB_DAT, R_ARM_JUMP_SLOT),
                "the symbol's GOT entry address",
            )
            return self._pack(
                got_entry + self._get_data_addend(rela, elf, 4) - rela.offset, 4
            )
        elif rela.type == R_ARM_PLT32_ABS:
            # This relocation needs the absolute address of the symbol's PLT entry.
            # The current inputs expose only the resolved symbol value, not the PLT layout.
            self._missing_context(rela, "the symbol's absolute PLT entry address")
        elif rela.type == R_ARM_TLS_GD32:
            pair_base = self._tls_pair_base(
                rela,
                (R_ARM_TLS_DTPMOD32, R_ARM_TLS_DTPOFF32),
                "the symbol's TLS GD GOT pair address",
            )
            return self._pack(
                pair_base + self._get_data_addend(rela, elf, 4) - rela.offset, 4
            )
        elif rela.type == R_ARM_TLS_LDM32:
            pair_base = self._tls_pair_base(
                rela,
                (R_ARM_TLS_DTPMOD32, R_ARM_TLS_DTPOFF32),
                "the module's TLS LD GOT pair address",
            )
            return self._pack(
                pair_base + self._get_data_addend(rela, elf, 4) - rela.offset, 4
            )
        elif rela.type == R_ARM_TLS_IE32:
            got_entry = self._proxy_offset(
                rela,
                (R_ARM_TLS_TPOFF32,),
                "the symbol's TLS IE GOT entry address",
            )
            return self._pack(
                got_entry + self._get_data_addend(rela, elf, 4) - rela.offset, 4
            )
        elif rela.type in (R_ARM_TLS_LDO32, R_ARM_TLS_DTPOFF32):
            # Dynamic and local-dynamic TLS offsets need the final layout of the
            # module's TLS block.
            self._missing_context(rela, "the symbol's offset within its TLS block")
        elif rela.type in (R_ARM_TLS_LE32, R_ARM_TLS_TPOFF32):
            # Thread-pointer-relative TLS relocations need the runtime TLS layout.
            self._missing_context(
                rela, "the symbol's thread-pointer-relative TLS offset"
            )
        elif rela.type == R_ARM_TLS_DTPMOD32:
            # TLS module relocations need the runtime-assigned TLS module ID.
            self._missing_context(rela, "the TLS module ID for the symbol")
        elif rela.type == R_ARM_COPY:
            # Copy relocations need the bytes stored at the resolved symbol,
            # not just the symbol's address.
            self._missing_context(rela, "the copied symbol's source bytes")
        elif rela.type == R_ARM_BREL_ADJ:
            # This dynamic relocation needs the change in the loaded segment base
            # relative to the image's linked address, which is not exposed here.
            self._missing_context(rela, "the segment-base adjustment delta")
        elif rela.type == R_ARM_TLS_DESC:
            # A TLSDESC relocation fills a descriptor pair in the GOT and needs
            # the descriptor contents and resolver state.
            self._missing_context(
                rela, "the TLS descriptor contents and resolver state"
            )
        elif rela.type == R_ARM_IRELATIVE:
            # Indirect relative relocations require executing an IFUNC resolver
            # and writing back its return value.
            self._missing_context(rela, "IFUNC resolver execution and its return value")

        elif rela.type in (R_ARM_LDR_PC_G0, R_ARM_LDR_PC_G1, R_ARM_LDR_PC_G2):
            value = sym + self._get_arm_mem12_addend(rela, elf) - rela.offset
            abs_value = abs(value)
            idx = {R_ARM_LDR_PC_G0: 0, R_ARM_LDR_PC_G1: 1, R_ARM_LDR_PC_G2: 2}[
                rela.type
            ]
            residual = self._arm_group_residual(abs_value, idx)
            self._check_range(residual, 0, 1 << 12, rela, "LDR_PC_Gn")
            orig = self._read_arm32(rela, elf)
            return self._pack_arm32(
                self._patch_arm_mem12(orig, residual if value >= 0 else -residual)
            )
        elif rela.type == R_ARM_ABS12:
            value = sym + self._get_arm_mem12_addend(rela, elf)
            self._check_range(abs(value), 0, 1 << 12, rela, "ABS12")
            orig = self._read_arm32(rela, elf)
            return self._pack_arm32(self._patch_arm_mem12(orig, value))
        elif rela.type in (R_ARM_PC24, R_ARM_PLT32, R_ARM_JUMP24):
            value = sym_t + self._get_arm_branch_addend(rela, elf) - rela.offset
            self._check_range(value & ~1, -(1 << 25), 1 << 25, rela, "Arm branch")
            if sym_t & 1:
                # Arm-state non-call branches to Thumb require either a veneer or
                # interworking branch synthesis, which this loader does not emit.
                self._missing_context(
                    rela, "Arm-to-Thumb veneer/interworking branch generation"
                )
            self._check_aligned(value, 4, rela, "Arm branch")
            return self._pack_arm32(
                self._patch_arm_branch(self._read_arm32(rela, elf), value)
            )
        elif rela.type == R_ARM_CALL:
            value = sym_t + self._get_arm_branch_addend(rela, elf) - rela.offset
            orig = self._read_arm32(rela, elf)
            if sym_t & 1:
                self._check_range(value & ~1, -(1 << 25), 1 << 25, rela, "Arm BLX call")
                self._check_aligned(value & ~1, 2, rela, "Arm BLX call")
                return self._pack_arm32(self._patch_arm_blx(value))
            if (orig >> 28) == 0xF:
                self._missing_context(
                    rela, "Thumb-target interworking for an Arm BLX call"
                )
            self._check_range(value, -(1 << 25), 1 << 25, rela, "Arm BL call")
            self._check_aligned(value, 4, rela, "Arm BL call")
            return self._pack_arm32(self._patch_arm_branch(orig, value))
        elif rela.type in (R_ARM_ALU_PCREL_7_0, R_ARM_ALU_PC_G0_NC, R_ARM_ALU_PC_G0):
            value = sym_t + self._get_arm_add_sub_addend(rela, elf) - rela.offset
            group, residual = self._arm_group_value(abs(value), 0)
            if rela.type == R_ARM_ALU_PC_G0:
                self._check_range(residual, 0, 1, rela, "ALU_PC_G0")
            orig = self._read_arm32(rela, elf)
            return self._pack_arm32(
                self._patch_arm_add_sub(
                    orig, group if value >= 0 else -group, rela, "ALU_PC_G0"
                )
            )
        elif rela.type in (R_ARM_ALU_PCREL_15_8, R_ARM_ALU_PC_G1_NC, R_ARM_ALU_PC_G1):
            value = sym_t + self._get_arm_add_sub_addend(rela, elf) - rela.offset
            group, residual = self._arm_group_value(abs(value), 1)
            if rela.type == R_ARM_ALU_PC_G1:
                self._check_range(residual, 0, 1, rela, "ALU_PC_G1")
            orig = self._read_arm32(rela, elf)
            return self._pack_arm32(
                self._patch_arm_add_sub(
                    orig, group if value >= 0 else -group, rela, "ALU_PC_G1"
                )
            )
        elif rela.type in (R_ARM_ALU_PCREL_23_15, R_ARM_ALU_PC_G2):
            value = sym_t + self._get_arm_add_sub_addend(rela, elf) - rela.offset
            group, residual = self._arm_group_value(abs(value), 2)
            self._check_range(residual, 0, 1, rela, "ALU_PC_G2")
            orig = self._read_arm32(rela, elf)
            return self._pack_arm32(
                self._patch_arm_add_sub(
                    orig, group if value >= 0 else -group, rela, "ALU_PC_G2"
                )
            )
        elif rela.type in (
            R_ARM_LDR_SBREL_11_0_NC,
            R_ARM_LDR_SB_G0,
            R_ARM_LDR_SB_G1,
            R_ARM_LDR_SB_G2,
        ):
            value = sym + self._get_arm_mem12_addend(rela, elf) - base
            if rela.type == R_ARM_LDR_SBREL_11_0_NC:
                residual = abs(value)
            else:
                idx = {R_ARM_LDR_SB_G0: 0, R_ARM_LDR_SB_G1: 1, R_ARM_LDR_SB_G2: 2}[
                    rela.type
                ]
                residual = self._arm_group_residual(abs(value), idx)
            self._check_range(residual, 0, 1 << 12, rela, "LDR_SB_Gn")
            orig = self._read_arm32(rela, elf)
            return self._pack_arm32(
                self._patch_arm_mem12(orig, residual if value >= 0 else -residual)
            )
        elif rela.type in (
            R_ARM_ALU_SBREL_19_12_NC,
            R_ARM_ALU_SB_G1_NC,
            R_ARM_ALU_SB_G1,
        ):
            value = sym_t + self._get_arm_add_sub_addend(rela, elf) - base
            group, residual = self._arm_group_value(abs(value), 1)
            if rela.type == R_ARM_ALU_SB_G1:
                self._check_range(residual, 0, 1, rela, "ALU_SB_G1")
            orig = self._read_arm32(rela, elf)
            return self._pack_arm32(
                self._patch_arm_add_sub(
                    orig, group if value >= 0 else -group, rela, "ALU_SB_G1"
                )
            )
        elif rela.type in (R_ARM_ALU_SBREL_27_20_CK, R_ARM_ALU_SB_G2):
            value = sym_t + self._get_arm_add_sub_addend(rela, elf) - base
            group, residual = self._arm_group_value(abs(value), 2)
            self._check_range(residual, 0, 1, rela, "ALU_SB_G2")
            orig = self._read_arm32(rela, elf)
            return self._pack_arm32(
                self._patch_arm_add_sub(
                    orig, group if value >= 0 else -group, rela, "ALU_SB_G2"
                )
            )
        elif rela.type in (R_ARM_ALU_SB_G0_NC, R_ARM_ALU_SB_G0):
            value = sym_t + self._get_arm_add_sub_addend(rela, elf) - base
            group, residual = self._arm_group_value(abs(value), 0)
            if rela.type == R_ARM_ALU_SB_G0:
                self._check_range(residual, 0, 1, rela, "ALU_SB_G0")
            orig = self._read_arm32(rela, elf)
            return self._pack_arm32(
                self._patch_arm_add_sub(
                    orig, group if value >= 0 else -group, rela, "ALU_SB_G0"
                )
            )
        elif rela.type in (R_ARM_LDRS_PC_G0, R_ARM_LDRS_PC_G1, R_ARM_LDRS_PC_G2):
            value = sym + self._get_arm_mem8_addend(rela, elf) - rela.offset
            idx = {R_ARM_LDRS_PC_G0: 0, R_ARM_LDRS_PC_G1: 1, R_ARM_LDRS_PC_G2: 2}[
                rela.type
            ]
            residual = self._arm_group_residual(abs(value), idx)
            self._check_range(residual, 0, 1 << 8, rela, "LDRS_PC_Gn")
            orig = self._read_arm32(rela, elf)
            return self._pack_arm32(
                self._patch_arm_mem8_split(orig, residual if value >= 0 else -residual)
            )
        elif rela.type in (R_ARM_LDRS_SB_G0, R_ARM_LDRS_SB_G1, R_ARM_LDRS_SB_G2):
            value = sym + self._get_arm_mem8_addend(rela, elf) - base
            idx = {R_ARM_LDRS_SB_G0: 0, R_ARM_LDRS_SB_G1: 1, R_ARM_LDRS_SB_G2: 2}[
                rela.type
            ]
            residual = self._arm_group_residual(abs(value), idx)
            self._check_range(residual, 0, 1 << 8, rela, "LDRS_SB_Gn")
            orig = self._read_arm32(rela, elf)
            return self._pack_arm32(
                self._patch_arm_mem8_split(orig, residual if value >= 0 else -residual)
            )
        elif rela.type in (R_ARM_LDC_PC_G0, R_ARM_LDC_PC_G1, R_ARM_LDC_PC_G2):
            value = sym + self._get_arm_ldc_addend(rela, elf) - rela.offset
            idx = {R_ARM_LDC_PC_G0: 0, R_ARM_LDC_PC_G1: 1, R_ARM_LDC_PC_G2: 2}[
                rela.type
            ]
            residual = self._arm_group_residual(abs(value), idx)
            self._check_aligned(residual, 4, rela, "LDC_PC_Gn")
            self._check_range(residual >> 2, 0, 1 << 8, rela, "LDC_PC_Gn")
            orig = self._read_arm32(rela, elf)
            return self._pack_arm32(
                self._patch_arm_ldc(orig, residual if value >= 0 else -residual)
            )
        elif rela.type in (R_ARM_LDC_SB_G0, R_ARM_LDC_SB_G1, R_ARM_LDC_SB_G2):
            value = sym + self._get_arm_ldc_addend(rela, elf) - base
            idx = {R_ARM_LDC_SB_G0: 0, R_ARM_LDC_SB_G1: 1, R_ARM_LDC_SB_G2: 2}[
                rela.type
            ]
            residual = self._arm_group_residual(abs(value), idx)
            self._check_aligned(residual, 4, rela, "LDC_SB_Gn")
            self._check_range(residual >> 2, 0, 1 << 8, rela, "LDC_SB_Gn")
            orig = self._read_arm32(rela, elf)
            return self._pack_arm32(
                self._patch_arm_ldc(orig, residual if value >= 0 else -residual)
            )
        elif rela.type == R_ARM_MOVW_ABS_NC:
            value = sym_t + self._get_arm_mov_addend(rela, elf)
            return self._pack_arm32(
                self._patch_arm_mov(self._read_arm32(rela, elf), value & 0xFFFF)
            )
        elif rela.type == R_ARM_MOVT_ABS:
            value = sym + self._get_arm_mov_addend(rela, elf)
            return self._pack_arm32(
                self._patch_arm_mov(self._read_arm32(rela, elf), (value >> 16) & 0xFFFF)
            )
        elif rela.type == R_ARM_MOVW_PREL_NC:
            value = sym_t + self._get_arm_mov_addend(rela, elf) - rela.offset
            return self._pack_arm32(
                self._patch_arm_mov(self._read_arm32(rela, elf), value & 0xFFFF)
            )
        elif rela.type == R_ARM_MOVT_PREL:
            value = sym + self._get_arm_mov_addend(rela, elf) - rela.offset
            return self._pack_arm32(
                self._patch_arm_mov(self._read_arm32(rela, elf), (value >> 16) & 0xFFFF)
            )
        elif rela.type == R_ARM_MOVW_BREL_NC:
            value = sym_t + self._get_arm_mov_addend(rela, elf) - base
            return self._pack_arm32(
                self._patch_arm_mov(self._read_arm32(rela, elf), value & 0xFFFF)
            )
        elif rela.type == R_ARM_MOVW_BREL:
            value = sym_t + self._get_arm_mov_addend(rela, elf) - base
            self._check_range(value, 0, 1 << 16, rela, "MOVW_BREL")
            return self._pack_arm32(
                self._patch_arm_mov(self._read_arm32(rela, elf), value & 0xFFFF)
            )
        elif rela.type == R_ARM_MOVT_BREL:
            value = sym + self._get_arm_mov_addend(rela, elf) - base
            return self._pack_arm32(
                self._patch_arm_mov(self._read_arm32(rela, elf), (value >> 16) & 0xFFFF)
            )
        elif rela.type == R_ARM_GOT_BREL12:
            got_entry = self._proxy_offset(
                rela,
                (R_ARM_GLOB_DAT, R_ARM_JUMP_SLOT),
                "the symbol's GOT entry address",
            )
            got_base = self._got_base(rela, elf)
            value = got_entry + self._get_arm_mem12_addend(rela, elf) - got_base
            self._check_range(abs(value), 0, 1 << 12, rela, "GOT_BREL12")
            orig = self._read_arm32(rela, elf)
            return self._pack_arm32(self._patch_arm_mem12(orig, value))
        elif rela.type == R_ARM_GOTOFF12:
            got_base = self._got_base(rela, elf)
            value = sym + self._get_arm_mem12_addend(rela, elf) - got_base
            self._check_range(abs(value), 0, 1 << 12, rela, "GOTOFF12")
            orig = self._read_arm32(rela, elf)
            return self._pack_arm32(self._patch_arm_mem12(orig, value))

        elif rela.type == R_ARM_THM_ABS5:
            value = sym + (
                rela.addend
                if rela.is_rela
                else ((self._read_thumb16(rela, elf) >> 6) & 0x1F) << 2
            )
            self._check_aligned(value, 4, rela, "THM_ABS5")
            self._check_range(value, 0, 1 << 7, rela, "THM_ABS5")
            orig = self._read_thumb16(rela, elf)
            return self._pack_thumb16(
                (orig & ~(0x1F << 6)) | (((value >> 2) & 0x1F) << 6)
            )
        elif rela.type == R_ARM_THM_PC8:
            value = sym + self._get_thumb_pc8_addend(rela, elf) - (rela.offset & ~3)
            self._check_aligned(value, 4, rela, "THM_PC8")
            self._check_range(value, 0, 1 << 10, rela, "THM_PC8")
            orig = self._read_thumb16(rela, elf)
            return self._pack_thumb16((orig & ~0xFF) | ((value >> 2) & 0xFF))
        elif rela.type == R_ARM_THM_CALL:
            if not (sym_t & 1):
                # Thumb-to-Arm calls need BLX conversion or a veneer. The current
                # loader does not synthesize those transitions.
                self._missing_context(
                    rela, "Thumb-to-Arm interworking call/veneer generation"
                )
            value = sym_t + self._get_thumb_bl_addend(rela, elf) - rela.offset
            self._check_range(value & ~1, -(1 << 24), 1 << 24, rela, "THM_CALL")
            patched = self._patch_thumb_bl(
                self._read_thumb32(rela, elf), value & 0x01FFFFFE
            )
            return self._pack_thumb32(patched)
        elif rela.type == R_ARM_THM_JUMP24:
            if not (sym_t & 1):
                self._missing_context(
                    rela, "Thumb-to-Arm interworking jump/veneer generation"
                )
            value = sym_t + self._get_thumb_bl_addend(rela, elf) - rela.offset
            self._check_range(value & ~1, -(1 << 24), 1 << 24, rela, "THM_JUMP24")
            patched = self._patch_thumb_bl(
                self._read_thumb32(rela, elf), value & 0x01FFFFFE
            )
            return self._pack_thumb32(patched)
        elif rela.type == R_ARM_THM_MOVW_ABS_NC:
            value = sym_t + self._get_thumb_mov_addend(rela, elf)
            return self._pack_thumb32(
                self._patch_thumb_mov(self._read_thumb32(rela, elf), value & 0xFFFF)
            )
        elif rela.type == R_ARM_THM_MOVT_ABS:
            value = sym + self._get_thumb_mov_addend(rela, elf)
            return self._pack_thumb32(
                self._patch_thumb_mov(
                    self._read_thumb32(rela, elf), (value >> 16) & 0xFFFF
                )
            )
        elif rela.type == R_ARM_THM_MOVW_PREL_NC:
            value = sym_t + self._get_thumb_mov_addend(rela, elf) - rela.offset
            return self._pack_thumb32(
                self._patch_thumb_mov(self._read_thumb32(rela, elf), value & 0xFFFF)
            )
        elif rela.type == R_ARM_THM_MOVT_PREL:
            value = sym + self._get_thumb_mov_addend(rela, elf) - rela.offset
            return self._pack_thumb32(
                self._patch_thumb_mov(
                    self._read_thumb32(rela, elf), (value >> 16) & 0xFFFF
                )
            )
        elif rela.type == R_ARM_THM_JUMP19:
            if not (sym_t & 1):
                self._missing_context(
                    rela, "Thumb-to-Arm conditional jump veneer generation"
                )
            value = sym_t + self._get_thumb_jump19_addend(rela, elf) - rela.offset
            self._check_range(value & ~1, -(1 << 20), 1 << 20, rela, "THM_JUMP19")
            patched = self._patch_thumb_jump19(
                self._read_thumb32(rela, elf), value & 0x001FFFFE
            )
            return self._pack_thumb32(patched)
        elif rela.type == R_ARM_THM_JUMP6:
            value = sym + self._get_thumb_jump6_addend(rela, elf) - rela.offset
            self._check_aligned(value, 2, rela, "THM_JUMP6")
            self._check_range(value, 0, 1 << 7, rela, "THM_JUMP6")
            orig = self._read_thumb16(rela, elf)
            patched = orig & ~((1 << 9) | (0x1F << 3))
            patched |= ((value >> 6) & 1) << 9
            patched |= ((value >> 1) & 0x1F) << 3
            return self._pack_thumb16(patched)
        elif rela.type == R_ARM_THM_ALU_PREL_11_0:
            value = sym_t + self._get_thumb_adr_addend(rela, elf) - (rela.offset & ~3)
            self._check_range(value, -(1 << 12), 1 << 12, rela, "THM_ALU_PREL_11_0")
            return self._pack_thumb32(
                self._patch_thumb_adr(self._read_thumb32(rela, elf), value)
            )
        elif rela.type == R_ARM_THM_PC12:
            value = (
                sym
                + self._get_thumb_mem12_addend(rela, elf, signed=True)
                - (rela.offset & ~3)
            )
            self._check_range(abs(value), 0, 1 << 12, rela, "THM_PC12")
            return self._pack_thumb32(
                self._patch_thumb_mem12(
                    self._read_thumb32(rela, elf), value, signed=True
                )
            )
        elif rela.type == R_ARM_THM_JUMP11:
            value = sym + self._get_thumb_branch16_addend(rela, elf, 11) - rela.offset
            self._check_aligned(value, 2, rela, "THM_JUMP11")
            self._check_range(value, -(1 << 11), 1 << 11, rela, "THM_JUMP11")
            orig = self._read_thumb16(rela, elf)
            return self._pack_thumb16((orig & ~0x7FF) | ((value >> 1) & 0x7FF))
        elif rela.type == R_ARM_THM_JUMP8:
            value = sym + self._get_thumb_branch16_addend(rela, elf, 8) - rela.offset
            self._check_aligned(value, 2, rela, "THM_JUMP8")
            self._check_range(value, -(1 << 8), 1 << 8, rela, "THM_JUMP8")
            orig = self._read_thumb16(rela, elf)
            return self._pack_thumb16((orig & ~0xFF) | ((value >> 1) & 0xFF))
        elif rela.type == R_ARM_THM_MOVW_BREL_NC:
            value = sym_t + self._get_thumb_mov_addend(rela, elf) - base
            return self._pack_thumb32(
                self._patch_thumb_mov(self._read_thumb32(rela, elf), value & 0xFFFF)
            )
        elif rela.type == R_ARM_THM_MOVT_BREL:
            value = sym + self._get_thumb_mov_addend(rela, elf) - base
            return self._pack_thumb32(
                self._patch_thumb_mov(
                    self._read_thumb32(rela, elf), (value >> 16) & 0xFFFF
                )
            )
        elif rela.type == R_ARM_THM_MOVW_BREL:
            value = sym_t + self._get_thumb_mov_addend(rela, elf) - base
            self._check_range(value, 0, 1 << 16, rela, "THM_MOVW_BREL")
            return self._pack_thumb32(
                self._patch_thumb_mov(self._read_thumb32(rela, elf), value & 0xFFFF)
            )
        elif rela.type == R_ARM_THM_GOT_BREL12:
            got_entry = self._proxy_offset(
                rela,
                (R_ARM_GLOB_DAT, R_ARM_JUMP_SLOT),
                "the symbol's GOT entry address",
            )
            got_base = self._got_base(rela, elf)
            value = (
                got_entry
                + self._get_thumb_mem12_addend(rela, elf, signed=False)
                - got_base
            )
            self._check_range(value, 0, 1 << 12, rela, "THM_GOT_BREL12")
            return self._pack_thumb32(
                self._patch_thumb_mem12(
                    self._read_thumb32(rela, elf), value, signed=False
                )
            )
        elif rela.type == R_ARM_THM_ALU_ABS_G0_NC:
            value = sym_t + self._get_thumb_imm8_addend(rela, elf)
            orig = self._read_thumb16(rela, elf)
            return self._pack_thumb16((orig & ~0xFF) | (value & 0xFF))
        elif rela.type == R_ARM_THM_ALU_ABS_G1_NC:
            value = sym + self._get_thumb_imm8_addend(rela, elf)
            orig = self._read_thumb16(rela, elf)
            return self._pack_thumb16((orig & ~0xFF) | ((value >> 8) & 0xFF))
        elif rela.type == R_ARM_THM_ALU_ABS_G2_NC:
            value = sym + self._get_thumb_imm8_addend(rela, elf)
            orig = self._read_thumb16(rela, elf)
            return self._pack_thumb16((orig & ~0xFF) | ((value >> 16) & 0xFF))
        elif rela.type == R_ARM_THM_ALU_ABS_G3:
            value = sym + self._get_thumb_imm8_addend(rela, elf)
            orig = self._read_thumb16(rela, elf)
            return self._pack_thumb16((orig & ~0xFF) | ((value >> 24) & 0xFF))
        elif rela.type == R_ARM_THM_BF16:
            value = sym_t + self._get_thumb_bf_addend(rela, elf, 17) - rela.offset
            masked = value & 0x0001FFFE
            if not (-(1 << 16) <= value < (1 << 16)):
                return self._pack_thumb32(THUMB_NOP_W)
            return self._pack_thumb32(
                self._patch_thumb_bf(self._read_thumb32(rela, elf), masked, rela.type)
            )
        elif rela.type == R_ARM_THM_BF12:
            value = sym_t + self._get_thumb_bf_addend(rela, elf, 13) - rela.offset
            masked = value & 0x00001FFE
            if not (-(1 << 12) <= value < (1 << 12)):
                return self._pack_thumb32(THUMB_NOP_W)
            return self._pack_thumb32(
                self._patch_thumb_bf(self._read_thumb32(rela, elf), masked, rela.type)
            )
        elif rela.type == R_ARM_THM_BF18:
            value = sym_t + self._get_thumb_bf_addend(rela, elf, 19) - rela.offset
            masked = value & 0x0007FFFE
            if not (-(1 << 18) <= value < (1 << 18)):
                return self._pack_thumb32(THUMB_NOP_W)
            return self._pack_thumb32(
                self._patch_thumb_bf(self._read_thumb32(rela, elf), masked, rela.type)
            )

        elif rela.type == R_ARM_TLS_LDO12:
            # Local-dynamic TLS offsets need the final layout of the module's TLS block.
            self._missing_context(rela, "the symbol's offset within its TLS block")
        elif rela.type == R_ARM_TLS_LE12:
            # Local-exec TLS offsets are relative to the runtime thread pointer.
            self._missing_context(
                rela, "the symbol's thread-pointer-relative TLS offset"
            )
        elif rela.type == R_ARM_TLS_IE12GP:
            got_entry = self._proxy_offset(
                rela,
                (R_ARM_TLS_TPOFF32,),
                "the symbol's TLS IE GOT entry address",
            )
            got_base = self._got_base(rela, elf)
            value = got_entry + self._get_arm_mem12_addend(rela, elf) - got_base
            self._check_range(abs(value), 0, 1 << 12, rela, "TLS_IE12GP")
            return self._pack_arm32(
                self._patch_arm_mem12(self._read_arm32(rela, elf), value)
            )
        elif rela.type == R_ARM_TLS_GOTDESC:
            # The experimental static TLSDESC relocations need the descriptor slot
            # address and sequence semantics from the TLSDESC ABI extension.
            self._missing_context(
                rela, "the TLSDESC GOT entry address and sequence semantics"
            )
        elif rela.type in (
            R_ARM_TLS_CALL,
            R_ARM_TLS_DESCSEQ,
            R_ARM_THM_TLS_CALL,
            R_ARM_THM_TLS_DESCSEQ16,
            R_ARM_THM_TLS_DESCSEQ32,
        ):
            # These relocations are sequence markers/relaxation tags for TLSDESC.
            return b""

        elif rela.type in (
            R_ARM_GOTRELAX,
            R_ARM_GNU_VTENTRY,
            R_ARM_GNU_VTINHERIT,
            R_ARM_V4BX,
        ):
            # These relocations are optimization or compatibility markers and do not
            # require a data write in this loader.
            return b""

        elif rela.type == R_ARM_TARGET1:
            # TARGET1 is platform-defined as either ABS32 or REL32 for init/fini arrays.
            self._missing_context(
                rela, "the platform-specific TARGET1 policy (ABS32 vs REL32)"
            )
        elif rela.type == R_ARM_TARGET2:
            # TARGET2 is platform-defined and only meaningful to the runtime support library.
            self._missing_context(
                rela, "the platform-specific TARGET2 relocation semantics"
            )

        elif rela.type in (R_ARM_THM_SWI8, R_ARM_XPC25, R_ARM_THM_XPC22, R_ARM_ME_TOO):
            raise ConfigurationError(
                f"Obsolete ARM relocation for {self._symbol_name(rela)}: {hex(rela.type)}"
            )
        elif (
            R_ARM_PRIVATE_0_LO <= rela.type <= R_ARM_PRIVATE_0_HI
            or R_ARM_PRIVATE_1_LO <= rela.type <= R_ARM_PRIVATE_1_HI
        ):
            # Private relocation ranges are interpreted by EI_OSABI / platform ABI rules.
            self._missing_context(
                rela, "platform-specific private relocation semantics"
            )
        elif (
            R_ARM_RESERVED_0_LO <= rela.type <= R_ARM_RESERVED_0_HI
            or R_ARM_RESERVED_1_LO <= rela.type <= R_ARM_RESERVED_1_HI
        ):
            raise ConfigurationError(
                f"Reserved ARM relocation for {self._symbol_name(rela)}: {hex(rela.type)}"
            )
        elif rela.type in (
            R_ARM_RXPC25,
            R_ARM_RSBREL32,
            R_ARM_THM_RPC22,
            R_ARM_RREL32,
            R_ARM_RABS22,
            R_ARM_RPC24,
            R_ARM_RBASE,
        ):
            # These legacy codes are listed by elf.h but are not defined by AAELF32.
            self._missing_context(rela, "legacy non-AAELF ARM relocation semantics")
        elif 0 <= rela.type < R_ARM_NUM:
            raise ConfigurationError(
                f"Valid, but unsupported relocation for "
                f"{self._symbol_name(rela)}: {rela.type}"
            )
        else:
            raise ConfigurationError(
                f"Invalid relocation type for "
                f"{self._symbol_name(rela)}: {hex(rela.type)}"
            )


class Armv5TElfRelocator(ArmElfRelocator):
    arch = platforms.Architecture.ARM_V5T


class Armv6MElfRelocator(ArmElfRelocator):
    arch = platforms.Architecture.ARM_V6M


class Armv7MElfRelocator(ArmElfRelocator):
    arch = platforms.Architecture.ARM_V7M


class Armv7RElfRelocator(ArmElfRelocator):
    arch = platforms.Architecture.ARM_V7R


class Armv7AElfRelocator(ArmElfRelocator):
    arch = platforms.Architecture.ARM_V7A
