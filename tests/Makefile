# This is a templated Makefile.
# Instead of explicitly writing out rules for every possible target,
# it uses formulaic parameter variables to duplicate
# the same set of rules for each architecture.

# ***********************
# *** Function Macros ***
# ***********************

# String to-lower macro
lc = $(subst A,a,$(subst B,b,$(subst C,c,$(subst D,d,$(subst E,e,$(subst F,f,$(subst G,g,$(subst H,h,$(subst I,i,$(subst J,j,$(subst K,k,$(subst L,l,$(subst M,m,$(subst N,n,$(subst O,o,$(subst P,p,$(subst Q,q,$(subst R,r,$(subst S,s,$(subst T,t,$(subst U,u,$(subst V,v,$(subst W,w,$(subst X,x,$(subst Y,y,$(subst Z,z,$1))))))))))))))))))))))))))

# ****************************
# *** Command Declarations ***
# ****************************

# Command Prefixes

AARCH64_ID := aarch64-linux-gnu.2.40
AARCH64BE_ID := aarch64_be-linux-gnu.2.40
AARCH64V85A_ID := $(AARCH64_ID)
AARCH64V85ABE_ID := $(AARCH64BE_ID)
AMD64_ID := x86_64-linux-gnu.2.40
AMD64_MINGW_ID := x86_64-windows-gnu.2.40
# 32-bit ARM is named by platform ID. The float ABI is implied by the
# platform: armv5t, armv6k, armv6m, armv7m, and armv8m are soft-float
# (gnueabi); armv7a, armv7r, armv8a, and armv8r hard-float (gnueabihf).
# armv8a is ARMv8-A in the AArch32 state. armv6m and armv7m are Thumb-only,
# so their sources start with `.thumb`. Each is pinned to a CPU via its ASFLAGS/CFLAGS,
# since zig otherwise targets ARMv7-A.
ARMV4_ID := arm-linux-gnueabi.2.40
ARMV4T_ID := arm-linux-gnueabi.2.40
ARMV5T_ID := arm-linux-gnueabi.2.40
# Big-endian ARMv4 and ARMv5 are BE32: lld links armeb as BE32 unless asked
# for BE8, which these cores don't support.
ARMV4BE_ID := armeb-linux-gnueabi.2.40
ARMV4TBE_ID := armeb-linux-gnueabi.2.40
ARMV5TBE_ID := armeb-linux-gnueabi.2.40
ARMV6K_ID := arm-linux-gnueabi.2.40
ARMV6M_ID := arm-linux-gnueabi.2.40
ARMV7A_ID := arm-linux-gnueabihf.2.40
ARMV7M_ID := arm-linux-gnueabi.2.40
ARMV7EM_ID := arm-linux-gnueabihf.2.40
ARMV8A_ID := arm-linux-gnueabihf.2.40
ARMV8M_ID := arm-linux-gnueabi.2.40
ARMV8R_ID := arm-linux-gnueabihf.2.40
ARMV7R_ID := arm-linux-gnueabihf.2.40
# Big-endian ARMv6 and later are BE8: lld links armeb for them as BE8, with
# code little-endian and data big-endian.
ARMV6KBE_ID := armeb-linux-gnueabi.2.40
ARMV7ABE_ID := armeb-linux-gnueabihf.2.40
ARMV7RBE_ID := armeb-linux-gnueabihf.2.40
ARMV8ABE_ID := armeb-linux-gnueabihf.2.40
ARMV8RBE_ID := armeb-linux-gnueabihf.2.40
I386_ID := x86-linux-gnu.2.40
I386_MINGW_ID := x86-windows-gnu.2.40
# zig has no LoongArch32 libc, and its LLVM no 32-bit LoongArch CPU to compile
# C for, so LoongArch32 tests are assembly only.
LA32_ID := loongarch32-linux
LA64_ID := loongarch64-linux-gnu.2.40
M68K_ID := m68k-unknown-linux-gnu
MIPS_ID := mips-linux-gnueabihf.2.40
MIPSEL_ID := mipsel-linux-gnueabihf.2.40
MIPS64_ID := mips64-linux.2.3.48-gnuabi64.2.40
MIPS64EL_ID := mips64el-linux.2.3.48-gnuabi64.2.40
MSP430_ID := msp430-linux-gnu
MSP430X_ID := msp430-linux-gnu
PPC_ID := powerpc-linux.1.3.45-gnueabi.2.40
PPC64_ID := powerpc64-linux-gnu.2.40
RISCV32_ID := riscv32-linux-gnu.2.40
RISCV64_ID := riscv64-linux-gnu.2.40
# One SuperH binutils covers SH-4 big/little and SH-2A; the generation and
# endianness come from per-platform ASFLAGS below.
SH_ID := sh4-unknown-linux-gnu
TRICORE_ID := tricore-elf
V850_ID := v850-elf
# zig's LLVM assembler has no PowerPC VLE; GNU binutils assembles it with -mvle.
PPCVLE_ID := powerpc-none-eabi
# Real-mode sources open with .code16; the 32-bit toolchain assembles them.
X86_16_ID := $(I386_ID)
XTENSA_ID := xtensa-lx106-elf

# Assembler Commands for Assembly

AARCH64_ASM_AS := zig build-exe -target $(AARCH64_ID) 
AARCH64BE_ASM_AS := zig build-exe -target $(AARCH64BE_ID)
AARCH64V85A_ASM_AS := zig build-exe -target $(AARCH64V85A_ID)
AARCH64V85ABE_ASM_AS := zig build-exe -target $(AARCH64V85ABE_ID)
AMD64_ASM_AS := ./nasm_wrapper.sh
# zig's own start code and compiler-rt return with bx, which ARMv4 lacks, so
# its assembly is linked freestanding without them. (build-obj would skip the
# link, but leaves every bl as an unresolved relocation: a branch to itself.)
ARMV4_ASM_AS := zig build-exe -target arm-freestanding-eabi -fno-compiler-rt
ARMV4T_ASM_AS := zig build-exe -target $(ARMV4T_ID)
ARMV5T_ASM_AS := zig build-exe -target $(ARMV5T_ID)
ARMV4BE_ASM_AS := zig build-exe -target armeb-freestanding-eabi -fno-compiler-rt
ARMV4TBE_ASM_AS := zig build-exe -target $(ARMV4TBE_ID)
ARMV5TBE_ASM_AS := zig build-exe -target $(ARMV5TBE_ID)
ARMV6K_ASM_AS := zig build-exe -target $(ARMV6K_ID)
# armv6m/armv7m build raw binaries only. build-obj skips linking, which would
# pull in zig's Linux start code; its syscall asm uses r7, which Thumb reserves.
ARMV6M_ASM_AS := zig build-obj -target $(ARMV6M_ID)
ARMV7A_ASM_AS := zig build-exe -target $(ARMV7A_ID)
ARMV7M_ASM_AS := zig build-obj -target $(ARMV7M_ID)
ARMV7EM_ASM_AS := zig build-obj -target $(ARMV7EM_ID)
ARMV8A_ASM_AS := zig build-exe -target $(ARMV8A_ID)
ARMV8M_ASM_AS := zig build-obj -target $(ARMV8M_ID)
ARMV8R_ASM_AS := zig build-exe -target $(ARMV8R_ID)
ARMV7R_ASM_AS := zig build-exe -target $(ARMV7R_ID)
ARMV6KBE_ASM_AS := zig build-exe -target $(ARMV6KBE_ID)
ARMV7ABE_ASM_AS := zig build-exe -target $(ARMV7ABE_ID)
ARMV7RBE_ASM_AS := zig build-exe -target $(ARMV7RBE_ID)
ARMV8ABE_ASM_AS := zig build-exe -target $(ARMV8ABE_ID)
ARMV8RBE_ASM_AS := zig build-exe -target $(ARMV8RBE_ID)
I386_ASM_AS := zig build-exe -target $(I386_ID)
LA32_ASM_AS := zig build-exe -target $(LA32_ID)
LA64_ASM_AS := zig build-exe -target $(LA64_ID)
M68K_ASM_AS := ./$(M68K_ID)-asm
MCS51_ASM_AS := ./mcs51_asm.sh
MIPS_ASM_AS := zig build-exe -target $(MIPS_ID)
MIPSEL_ASM_AS := zig build-exe -target $(MIPSEL_ID)
# microMIPS shares the MIPS32 targets; each source opens with `.set micromips`.
# (zig cannot build its runtime with -mcpu=...+micromips.)
MICROMIPS_ASM_AS := $(MIPS_ASM_AS)
MICROMIPSEL_ASM_AS := $(MIPSEL_ASM_AS)
MIPS64_ASM_AS := zig build-exe -target $(MIPS64_ID)
MIPS64EL_ASM_AS := zig build-exe -target $(MIPS64EL_ID)
MSP430_ASM_AS := zig build-exe -target $(MSP430_ID)
MSP430X_ASM_AS := zig build-exe -target $(MSP430X_ID)
PPC_ASM_AS := zig build-exe -target $(PPC_ID)
PPC64_ASM_AS := zig build-exe -target $(PPC64_ID)
RISCV32_ASM_AS := zig build-exe -target $(RISCV32_ID)
RISCV64_ASM_AS := zig build-exe -target $(RISCV64_ID)
SH4_ASM_AS := ./$(SH_ID)-asm
SH4EL_ASM_AS := ./$(SH_ID)-asm
SH2A_ASM_AS := ./$(SH_ID)-asm
SH2_ASM_AS := ./$(SH_ID)-asm
SH1_ASM_AS := ./$(SH_ID)-asm
TRICORE_ASM_AS := ./$(TRICORE_ID)-asm
V850_ASM_AS := ./$(V850_ID)-asm
PPCVLE_ASM_AS := ./$(PPCVLE_ID)-asm
XTENSA_ASM_AS := ./$(XTENSA_ID)-asm
X86_16_ASM_AS := zig build-exe -target $(X86_16_ID)

# Assembler Commands for ELF

AARCH64_ELF_AS := zig build-exe -target $(AARCH64_ID) 
AARCH64BE_ELF_AS := zig build-exe -target $(AARCH64BE_ID)
AARCH64V85A_ELF_AS := zig build-exe -target $(AARCH64V85A_ID)
AARCH64V85ABE_ELF_AS := zig build-exe -target $(AARCH64V85ABE_ID)
AMD64_ELF_AS := zig build-exe -target $(AMD64_ID)
ARMV4_ELF_AS := zig build-exe -target arm-freestanding-eabi -fno-compiler-rt
ARMV4T_ELF_AS := zig build-exe -target $(ARMV4T_ID)
ARMV5T_ELF_AS := zig build-exe -target $(ARMV5T_ID)
ARMV4BE_ELF_AS := zig build-exe -target armeb-freestanding-eabi -fno-compiler-rt
ARMV4TBE_ELF_AS := zig build-exe -target $(ARMV4TBE_ID)
ARMV5TBE_ELF_AS := zig build-exe -target $(ARMV5TBE_ID)
ARMV6K_ELF_AS := zig build-exe -target $(ARMV6K_ID)
# The M profile's assembly needs no runtime, and zig's compiler-rt doesn't
# build for ARMv6-M (see ARMV6M_ELF_CFLAGS).
ARMV6M_ELF_AS := zig build-exe -target thumb-freestanding-eabi -fno-compiler-rt
ARMV7A_ELF_AS := zig build-exe -target $(ARMV7A_ID)
ARMV7M_ELF_AS := zig build-exe -target thumb-freestanding-eabi -fno-compiler-rt
ARMV7EM_ELF_AS := zig build-exe -target thumb-freestanding-eabihf -fno-compiler-rt
ARMV7R_ELF_AS := zig build-exe -target $(ARMV7R_ID)
ARMV8A_ELF_AS := zig build-exe -target $(ARMV8A_ID)
ARMV8M_ELF_AS := zig build-exe -target thumb-freestanding-eabi -fno-compiler-rt
ARMV8R_ELF_AS := zig build-exe -target $(ARMV8R_ID)
ARMV6KBE_ELF_AS := zig build-exe -target $(ARMV6KBE_ID)
ARMV7ABE_ELF_AS := zig build-exe -target $(ARMV7ABE_ID)
ARMV7RBE_ELF_AS := zig build-exe -target $(ARMV7RBE_ID)
ARMV8ABE_ELF_AS := zig build-exe -target $(ARMV8ABE_ID)
ARMV8RBE_ELF_AS := zig build-exe -target $(ARMV8RBE_ID)
I386_ELF_AS := zig build-exe -target $(I386_ID) 
LA32_ELF_AS := zig build-exe -target $(LA32_ID)
LA64_ELF_AS := zig build-exe -target $(LA64_ID)
M68K_ELF_AS := ./$(M68K_ID)-elfasm
MIPS_ELF_AS := zig build-exe -target $(MIPS_ID)
MIPSEL_ELF_AS := zig build-exe -target $(MIPSEL_ID)
MICROMIPS_ELF_AS := $(MIPS_ELF_AS)
MICROMIPSEL_ELF_AS := $(MIPSEL_ELF_AS)
MIPS64_ELF_AS := zig build-exe -target $(MIPS64_ID) 
MIPS64EL_ELF_AS := zig build-exe -target $(MIPS64EL_ID) 
MSP430_ELF_AS := zig build-exe -target $(MSP430_ID)
MSP430X_ELF_AS := zig build-exe -target $(MSP430X_ID)
PPC_ELF_AS := zig build-exe -target $(PPC_ID)
PPC64_ELF_AS := zig build-exe -target $(PPC64_ID) 
RISCV32_ELF_AS := zig build-exe -target $(RISCV32_ID) 
RISCV64_ELF_AS := zig build-exe -target $(RISCV64_ID) 
SH4_ELF_AS := ./$(SH_ID)-elfasm
SH4EL_ELF_AS := ./$(SH_ID)-elfasm
SH2A_ELF_AS := ./$(SH_ID)-elfasm
SH2_ELF_AS := ./$(SH_ID)-elfasm
SH1_ELF_AS := ./$(SH_ID)-elfasm
TRICORE_ELF_AS := ./$(TRICORE_ID)-elfasm
V850_ELF_AS := ./$(V850_ID)-elfasm
PPCVLE_ELF_AS := ./$(PPCVLE_ID)-elfasm
XTENSA_ELF_AS := ./$(XTENSA_ID)-elfasm

# Objcopy Commands

AARCH64_OBJCOPY := zig objcopy
AARCH64BE_OBJCOPY := zig objcopy
AARCH64V85A_OBJCOPY := zig objcopy
AARCH64V85ABE_OBJCOPY := zig objcopy
# NASM doesn't produce a .o; we can skip this
AMD64_OBJCOPY := bash -c 'cp -- $$4 $$5'
ARMV4_OBJCOPY := zig objcopy
ARMV4T_OBJCOPY := zig objcopy
ARMV5T_OBJCOPY := zig objcopy
ARMV4BE_OBJCOPY := zig objcopy
ARMV4TBE_OBJCOPY := zig objcopy
ARMV5TBE_OBJCOPY := zig objcopy
ARMV6K_OBJCOPY := zig objcopy
ARMV6M_OBJCOPY := zig objcopy
ARMV7A_OBJCOPY := zig objcopy
ARMV7M_OBJCOPY := zig objcopy
ARMV7EM_OBJCOPY := zig objcopy
ARMV8A_OBJCOPY := zig objcopy
ARMV8M_OBJCOPY := zig objcopy
ARMV8R_OBJCOPY := zig objcopy
ARMV7R_OBJCOPY := zig objcopy
ARMV6KBE_OBJCOPY := zig objcopy
ARMV7ABE_OBJCOPY := zig objcopy
ARMV7RBE_OBJCOPY := zig objcopy
ARMV8ABE_OBJCOPY := zig objcopy
ARMV8RBE_OBJCOPY := zig objcopy
I386_OBJCOPY := zig objcopy
LA32_OBJCOPY := zig objcopy
LA64_OBJCOPY := zig objcopy
M68K_OBJCOPY := $(M68K_ID)-objcopy
# mcs51_asm.sh already writes the raw binary; see that script.
MCS51_OBJCOPY := bash -c 'cp -- $$4 $$5'
MIPS_OBJCOPY := zig objcopy
MIPSEL_OBJCOPY := zig objcopy
MICROMIPS_OBJCOPY := zig objcopy
MICROMIPSEL_OBJCOPY := zig objcopy
MIPS64_OBJCOPY := zig objcopy
MIPS64EL_OBJCOPY := zig objcopy
MSP430_OBJCOPY := zig objcopy
MSP430X_OBJCOPY := zig objcopy
PPC_OBJCOPY := zig objcopy
PPC64_OBJCOPY := zig objcopy
RISCV32_OBJCOPY := zig objcopy
RISCV64_OBJCOPY := zig objcopy
SH4_OBJCOPY := $(SH_ID)-objcopy
SH4EL_OBJCOPY := $(SH_ID)-objcopy
SH2A_OBJCOPY := $(SH_ID)-objcopy
SH2_OBJCOPY := $(SH_ID)-objcopy
SH1_OBJCOPY := $(SH_ID)-objcopy
TRICORE_OBJCOPY := $(TRICORE_ID)-objcopy
V850_OBJCOPY := $(V850_ID)-objcopy
PPCVLE_OBJCOPY := $(PPCVLE_ID)-objcopy
XTENSA_OBJCOPY := $(XTENSA_ID)-objcopy
X86_16_OBJCOPY := zig objcopy

# C compiler commands

AARCH64_CC := zig cc -target $(AARCH64_ID) 
AARCH64BE_CC := zig cc -target $(AARCH64BE_ID)
AARCH64V85A_CC := zig cc -target $(AARCH64V85A_ID)
AARCH64V85ABE_CC := zig cc -target $(AARCH64V85ABE_ID)
AMD64_CC := zig cc -target $(AMD64_ID)  
AMD64_MINGW_CC := zig cc -target $(AMD64_MINGW_ID) 
ARMV4T_CC := zig cc -target $(ARMV4T_ID)
ARMV5T_CC := zig cc -target $(ARMV5T_ID)
ARMV4TBE_CC := zig cc -target $(ARMV4TBE_ID)
ARMV5TBE_CC := zig cc -target $(ARMV5TBE_ID)
ARMV6K_CC := zig cc -target $(ARMV6K_ID)
ARMV7A_CC := zig cc -target $(ARMV7A_ID)
ARMV7R_CC := zig cc -target $(ARMV7R_ID)
ARMV8A_CC := zig cc -target $(ARMV8A_ID)
# glibc can't build for the Thumb-only M profile (its syscall asm uses r7,
# which Thumb reserves), so their C tests build against musl instead.
ARMV6M_CC := zig cc -target thumb-linux-musleabi
ARMV7M_CC := zig cc -target thumb-linux-musleabi
ARMV7EM_CC := zig cc -target thumb-linux-musleabihf
ARMV8M_CC := zig cc -target thumb-linux-musleabi
ARMV8R_CC := zig cc -target $(ARMV8R_ID)
ARMV6KBE_CC := zig cc -target $(ARMV6KBE_ID)
ARMV7ABE_CC := zig cc -target $(ARMV7ABE_ID)
ARMV7RBE_CC := zig cc -target $(ARMV7RBE_ID)
ARMV8ABE_CC := zig cc -target $(ARMV8ABE_ID)
ARMV8RBE_CC := zig cc -target $(ARMV8RBE_ID)
I386_CC := zig cc -target $(I386_ID) 
I386_MINGW_CC := zig cc -target $(I386_MINGW_ID) 
LA64_CC := zig cc -target $(LA64_ID) 
M68K_CC := $(M68K_ID)-gcc
MIPS_CC := zig cc -target $(MIPS_ID) 
MIPSEL_CC := zig cc -target $(MIPSEL_ID) 
MICROMIPS_CC := zig cc -target $(MIPS_ID)
MICROMIPSEL_CC := zig cc -target $(MIPSEL_ID)
MIPS64_CC := zig cc -target $(MIPS64_ID) 
MIPS64EL_CC := zig cc -target $(MIPS64EL_ID) 
MSP430_CC := zig cc -target $(MSP430_ID)
MSP430X_CC := zig cc -target $(MSP430X_ID)
PPC_CC := zig cc -target $(PPC_ID) 
PPC64_CC := zig cc -target $(PPC64_ID) 
RISCV32_CC := zig cc -target $(RISCV32_ID)
RISCV64_CC := zig cc -target $(RISCV64_ID)
TRICORE_CC := $(TRICORE_ID)-gcc
XTENSA_CC := $(XTENSA_ID)-gcc

# *************************
# *** Flag Declarations ***
# *************************

GENERAL_ASFLAGS := $(ASFLAGS)
# ARM CPUs: ARMv5T matches Panda's ARM926; ARMv7-A matches the Cortex-A9 that
# Panda and Styx use, a subset of Unicorn's Cortex-A15.
ARMV4_ASFLAGS := -mcpu=strongarm
ARMV4T_ASFLAGS := -mcpu=arm7tdmi
ARMV5T_ASFLAGS := -mcpu=arm926ej_s
ARMV4BE_ASFLAGS := $(ARMV4_ASFLAGS)
ARMV4TBE_ASFLAGS := $(ARMV4T_ASFLAGS)
ARMV5TBE_ASFLAGS := $(ARMV5T_ASFLAGS)
ARMV6K_ASFLAGS := -mcpu=arm1176jzf_s
ARMV6M_ASFLAGS := -mcpu=cortex_m0
ARMV7A_ASFLAGS := -mcpu=cortex_a9
ARMV7M_ASFLAGS := -mcpu=cortex_m3
# zig's cortex_m4 model has no FPU; the Cortex-M4F's FPv4-SP is vfp4d16sp.
ARMV7EM_ASFLAGS := -mcpu=cortex_m4+vfp4d16sp
ARMV8A_ASFLAGS := -mcpu=cortex_a53
ARMV8M_ASFLAGS := -mcpu=cortex_m33
ARMV8R_ASFLAGS := -mcpu=cortex_r52
ARMV7R_ASFLAGS := -mcpu=cortex_r5
ARMV6KBE_ASFLAGS := $(ARMV6K_ASFLAGS)
ARMV7ABE_ASFLAGS := $(ARMV7A_ASFLAGS)
ARMV7RBE_ASFLAGS := $(ARMV7R_ASFLAGS)
ARMV8ABE_ASFLAGS := $(ARMV8A_ASFLAGS)
ARMV8RBE_ASFLAGS := $(ARMV8R_ASFLAGS)
MSP430_ASFLAGS := -fno-sanitize-c -fno-builtin -fno-compiler-rt
MSP430X_ASFLAGS := -mcpu msp430x -fno-sanitize-c -fno-builtin -fno-compiler-rt
XTENSA_ASFLAGS := --no-transform --target-align --text-section-literals
SH4_ASFLAGS := -big --isa=sh4a
SH4EL_ASFLAGS := -little --isa=sh4a
SH2A_ASFLAGS := -big --isa=sh2a
SH2_ASFLAGS := -big --isa=sh2
# gas spells SH-1 plain `sh`.
SH1_ASFLAGS := -big --isa=sh
# GCC's ELF ABI (EM_V850, with the core in e_flags) rather than gas's RH850
# default (EM_V800). V850E1 is the oldest core Ghidra's language models, so
# the tests use only instructions every modelled core has.
V850_ASFLAGS := -mgcc-abi -mv850e1
PPCVLE_ASFLAGS := -mvle

# objcopy flags
GENERAL_OBJCOPYFLAGS := $(OBJCOPYFLAGS)

# ld flags
GENERAL_LDFLAGS := $(LDFLAGS)
MIPS64_LDFLAGS := -T mips_linkerscript.ld 
MIPS64EL_LDFLAGS := -T mips_linkerscript.ld 

# C flags
GENERAL_CFLAGS := $(CFLAGS) -g -O0 -fno-sanitize=undefined -fno-stack-protector -fno-builtin -Wno-deprecated-declarations -D_FORTIFY_SOURCE=0
ARMV4T_CFLAGS := -marm -mfloat-abi=soft -mcpu=arm7tdmi
ARMV5T_CFLAGS := -marm -mfloat-abi=soft -mcpu=arm926ej_s
ARMV4TBE_CFLAGS := $(ARMV4T_CFLAGS)
ARMV5TBE_CFLAGS := $(ARMV5T_CFLAGS)
ARMV6K_CFLAGS := -marm -mfloat-abi=soft -mcpu=arm1176jzf_s
# lld's PLT entries are Thumb-2, so ARMv6-M code calls through addresses
# loaded from its literal pools instead; see ARMV6M_ELF_CFLAGS.
ARMV6M_CFLAGS := -mcpu=cortex_m0 -mfloat-abi=soft -mlong-calls
ARMV7A_CFLAGS := -marm -mcpu=cortex_a9
ARMV7M_CFLAGS := -mcpu=cortex_m3 -mfloat-abi=soft
# Without +vfp4d16sp (see ARMV7EM_ASFLAGS), zig builds soft-float code even
# with -mfloat-abi=hard.
ARMV7EM_CFLAGS := -mcpu=cortex_m4+vfp4d16sp -mfloat-abi=hard
ARMV7R_CFLAGS := -marm -mcpu=cortex_r5
# zig assembles .s files for its baseline CPU whatever -mcpu says, so
# ARMv8.5-A sources enable their instructions with an .arch directive.
AARCH64V85A_CFLAGS := -mcpu=generic+v8_5a
AARCH64V85ABE_CFLAGS := -mcpu=generic+v8_5a
ARMV8A_CFLAGS := -marm -mcpu=cortex_a53
ARMV8M_CFLAGS := -mcpu=cortex_m33 -mfloat-abi=soft
ARMV8R_CFLAGS := -marm -mcpu=cortex_r52
ARMV6KBE_CFLAGS := $(ARMV6K_CFLAGS)
# At -O0, LLVM's FastISel passes a variadic double from a VFP register in
# r2:r3 low word first even on big-endian, where AAPCS puts the high word
# first; SelectionDAG gets it right, so use that.
BE8_HF_CFLAGS := -mllvm -fast-isel=false
ARMV7ABE_CFLAGS := $(ARMV7A_CFLAGS) $(BE8_HF_CFLAGS)
ARMV7RBE_CFLAGS := $(ARMV7R_CFLAGS) $(BE8_HF_CFLAGS)
ARMV8ABE_CFLAGS := $(ARMV8A_CFLAGS) $(BE8_HF_CFLAGS)
ARMV8RBE_CFLAGS := $(ARMV8R_CFLAGS) $(BE8_HF_CFLAGS)
LA64_CFLAGS := -mno-lsx
MIPS_CFLAGS := -mfloat-abi=hard
MIPSEL_CFLAGS := -mfloat-abi=hard
# zig cannot build its runtime or libc for microMIPS, and LLD cannot link
# microMIPS PIC calls (R_MICROMIPS_JALR), so microMIPS C is freestanding,
# non-PIC and static, entered at main. Only sources that need no library build.
MICROMIPS_CFLAGS := -mmicromips -fno-pic -mno-abicalls -nostdlib -static
MICROMIPSEL_CFLAGS := $(MICROMIPS_CFLAGS)
MICROMIPS_ELF_CFLAGS := -Wl,-e,main
MICROMIPSEL_ELF_CFLAGS := $(MICROMIPS_ELF_CFLAGS)
MICROMIPS_C_ELF_ONLY := exitpoint/exitpoint.elf.c unmapped/unmapped.elf.c
MICROMIPSEL_C_ELF_ONLY := $(MICROMIPS_C_ELF_ONLY)
MIPS64_CFLAGS := -T mips_linkerscript.ld
MIPS64EL_CFLAGS := -T mips_linkerscript.ld
PPC_CFLAGS := -mfloat-abi=hard

# ELF Executable C flags
AARCH64_ELF_CFLAGS := -pie
AARCH64BE_ELF_CFLAGS := -pie
AARCH64V85A_ELF_CFLAGS := -pie
AARCH64V85ABE_ELF_CFLAGS := -pie
AMD64_ELF_CFLAGS := -pie
ARMV7A_ELF_CFLAGS := -pie
ARMV7R_ELF_CFLAGS := -pie
# zig's compiler-rt needs libgcc's __sync_* atomics on ARMv4T and ARMv5, which
# zig doesn't ship; see arm_sync_shims.c. ARMv4 has no C tests: glibc's start
# code and zig's compiler-rt return with bx, which it lacks.
ARMV4T_ELF_LDLIBS := arm_sync_shims.c
ARMV5T_ELF_LDLIBS := arm_sync_shims.c
ARMV4TBE_ELF_LDLIBS := arm_sync_shims.c
ARMV5TBE_ELF_LDLIBS := arm_sync_shims.c
ARMV8A_ELF_CFLAGS := -pie
# zig links musl statically by default, which leaves no library imports for
# the models to replace.
ARMV7M_ELF_CFLAGS := -dynamic
ARMV7EM_ELF_CFLAGS := -dynamic
ARMV8M_ELF_CFLAGS := -dynamic
# zig can't link a Linux program for ARMv6-M: its musl start code and its
# compiler-rt use Thumb-2 instructions. So ARMv6-M ELFs compile for the
# Cortex-M0, but link for the Cortex-M3 (giving Thumb-2 start code, which the
# tests never run, as they start at main), without zig's compiler-rt, and
# with compiler-rt built for the Cortex-M0 instead. They link as PIEs, so the
# literal-pool addresses of library functions become dynamic relocations,
# which the models fill in, rather than addresses of Thumb-2 PLT entries.
#
# These aren't realistic ARMv6-M programs (real ones are bare-metal and
# statically linked), and they test a different linking path than the other
# ARM platforms: imports are R_ARM_ABS32 text relocations, not GOT entries
# (JUMP_SLOT, GLOB_DAT), every call is a literal-pool load and blx, shared
# objects can't interpose on their own functions, and the build attributes
# say Cortex-M3. GOT linking for the M profile is covered by ARMv7-M and
# ARMv8-M.
ARMV6M_ELF_CFLAGS := -dynamic -pie -Wl,-z,notext
ARMV6M_ELF_LINK_CFLAGS := -mcpu=cortex_m3 -mfloat-abi=soft -rtlib=none -Wl,--gc-sections
ARMV6M_ELF_LDLIBS := compiler_rt.armv6m.o
ARMV6M_ELF_DEPS := compiler_rt.armv6m.o
# A shared object's long calls to its own functions bind directly, rather than
# through lld's PLT, which is ARM code here.
ARMV6M_SO_CFLAGS := -Wl,-Bsymbolic -Wl,-z,notext

# C tests a platform can't build, by source. musl lacks these glibc-specific
# functions, or the tests use glibc's internal types (sigset_t's members).
MUSL_C_ELF_UNBUILDABLE := \
	c99/ctype_tolower_loc c99/ctype_toupper_loc c99/gets \
	c99/__fprintf_chk c99/__printf_chk c99/__snprintf_chk c99/__sprintf_chk \
	posix/bsd_signal posix/pthread_sigmask posix/sigaction posix/sigaddset \
	posix/sigdelset posix/sigemptyset posix/sigfillset posix/sigpending \
	posix/sigprocmask
MUSL_C_ELF_EXCLUDE := $(foreach t,$(MUSL_C_ELF_UNBUILDABLE),$(t)/$(notdir $(t)).elf.c)
ARMV6M_C_ELF_EXCLUDE := $(MUSL_C_ELF_EXCLUDE)
ARMV7M_C_ELF_EXCLUDE := $(MUSL_C_ELF_EXCLUDE)
ARMV7EM_C_ELF_EXCLUDE := $(MUSL_C_ELF_EXCLUDE)
ARMV8M_C_ELF_EXCLUDE := $(MUSL_C_ELF_EXCLUDE)
ARMV8R_ELF_CFLAGS := -pie
ARMV7ABE_ELF_CFLAGS := -pie
ARMV7RBE_ELF_CFLAGS := -pie
ARMV8ABE_ELF_CFLAGS := -pie
ARMV8RBE_ELF_CFLAGS := -pie
I386_ELF_CFLAGS := -pie
PPC64_ELF_CFLAGS := -pie
RISCV32_ELF_CFLAGS := -pie
RISCV64_ELF_CFLAGS := -pie
XTENSA_ELF_CFLAGS := -pie

# Extra link libraries, per architecture. Most toolchains resolve libm
# implicitly (or fold fabs and friends inline), but m68k-gcc needs it linked.
M68K_ELF_LDLIBS := -lm

# ***************************
# *** Template Parameters ***
# ***************************

# Arch-specific extensions.
AARCH64_EXT := aarch64
AARCH64BE_EXT := aarch64be
AARCH64V85A_EXT := aarch64v85a
AARCH64V85ABE_EXT := aarch64v85abe
AMD64_EXT := amd64
AMD64_MINGW_EXT := amd64
ARMV4_EXT := armv4
ARMV4T_EXT := armv4t
ARMV5T_EXT := armv5t
ARMV4BE_EXT := armv4be
ARMV4TBE_EXT := armv4tbe
ARMV5TBE_EXT := armv5tbe
ARMV6K_EXT := armv6k
ARMV6M_EXT := armv6m
ARMV7A_EXT := armv7a
ARMV7M_EXT := armv7m
ARMV7EM_EXT := armv7em
ARMV8A_EXT := armv8a
ARMV8M_EXT := armv8m
ARMV8R_EXT := armv8r
ARMV7R_EXT := armv7r
ARMV6KBE_EXT := armv6kbe
ARMV7ABE_EXT := armv7abe
ARMV7RBE_EXT := armv7rbe
ARMV8ABE_EXT := armv8abe
ARMV8RBE_EXT := armv8rbe
I386_EXT := i386
I386_MINGW_EXT := i386
LA32_EXT := la32
LA64_EXT := la64
M68K_EXT := m68k
MCS51_EXT := mcs51
MIPS_EXT := mips
MIPSEL_EXT := mipsel
MICROMIPS_EXT := micromips
MICROMIPSEL_EXT := micromipsel
MIPS64_EXT := mips64
MIPS64EL_EXT := mips64el
MSP430_EXT := msp430
MSP430X_EXT := msp430x
PPC_EXT := ppc
PPC64_EXT := ppc64
PPCVLE_EXT := ppcvle
RISCV32_EXT := riscv32
RISCV64_EXT := riscv64
SH4_EXT := sh4
SH4EL_EXT := sh4el
SH2A_EXT := sh2a
SH2_EXT := sh2
SH1_EXT := sh1
TRICORE_EXT := tricore
V850_EXT := v850
XTENSA_EXT := xtensa
X86_16_EXT := x86_16

# Arch-specific source extensions
AARCH64_SRC_EXT := $(AARCH64_EXT)
AARCH64BE_SRC_EXT := $(AARCH64_EXT)
AARCH64V85A_SRC_EXT := $(AARCH64_EXT)
AARCH64V85ABE_SRC_EXT := $(AARCH64_EXT)
AMD64_SRC_EXT := $(AMD64_EXT)
ARMV4_SRC_EXT := $(ARMV4_EXT)
ARMV4T_SRC_EXT := $(ARMV4T_EXT)
ARMV5T_SRC_EXT := $(ARMV5T_EXT)
ARMV4BE_SRC_EXT := $(ARMV4_EXT)
ARMV4TBE_SRC_EXT := $(ARMV4T_EXT)
ARMV5TBE_SRC_EXT := $(ARMV5T_EXT)
ARMV6K_SRC_EXT := $(ARMV6K_EXT)
ARMV6M_SRC_EXT := $(ARMV6M_EXT)
ARMV7A_SRC_EXT := $(ARMV7A_EXT)
ARMV7M_SRC_EXT := $(ARMV7M_EXT)
ARMV7EM_SRC_EXT := $(ARMV7EM_EXT)
ARMV8A_SRC_EXT := $(ARMV8A_EXT)
ARMV8M_SRC_EXT := $(ARMV8M_EXT)
ARMV8R_SRC_EXT := $(ARMV8R_EXT)
ARMV7R_SRC_EXT := $(ARMV7R_EXT)
ARMV6KBE_SRC_EXT := $(ARMV6K_EXT)
ARMV7ABE_SRC_EXT := $(ARMV7A_EXT)
ARMV7RBE_SRC_EXT := $(ARMV7R_EXT)
ARMV8ABE_SRC_EXT := $(ARMV8A_EXT)
ARMV8RBE_SRC_EXT := $(ARMV8R_EXT)
I386_SRC_EXT := $(I386_EXT)
LA32_SRC_EXT := $(LA32_EXT)
LA64_SRC_EXT := $(LA64_EXT)
M68K_SRC_EXT := $(M68K_EXT)
MCS51_SRC_EXT := $(MCS51_EXT)
MIPS_SRC_EXT := $(MIPS_EXT)
# NOTE: mipsel uses mips source
MIPSEL_SRC_EXT := $(MIPS_EXT)
MICROMIPS_SRC_EXT := $(MICROMIPS_EXT)
# NOTE: micromipsel uses micromips source
MICROMIPSEL_SRC_EXT := $(MICROMIPS_EXT)
MIPS64_SRC_EXT := $(MIPS64_EXT)
# NOTE: mips64el uses mips64 source
MIPS64EL_SRC_EXT := $(MIPS64_EXT)
MSP430_SRC_EXT := $(MSP430_EXT)
MSP430X_SRC_EXT := $(MSP430X_EXT)
PPC_SRC_EXT := $(PPC_EXT)
PPC64_SRC_EXT := $(PPC64_EXT)
PPCVLE_SRC_EXT := $(PPCVLE_EXT)
RISCV32_SRC_EXT := $(RISCV32_EXT)
RISCV64_SRC_EXT := $(RISCV64_EXT)
SH4_SRC_EXT := $(SH4_EXT)
# NOTE: sh4el uses sh4 source
SH4EL_SRC_EXT := $(SH4_EXT)
SH2A_SRC_EXT := $(SH2A_EXT)
SH2_SRC_EXT := $(SH2_EXT)
# NOTE: sh1 uses sh2 source, so the SH-1 build keeps that source SH-1-clean:
# gas refuses an instruction the --isa lacks.
SH1_SRC_EXT := $(SH2_EXT)
# ...except for the sh2 sources that test SH-2 additions, which SH-1 lacks.
SH1_SRC_EXCLUDE := sh2a_delayslot/sh2a_delayslot.sh2.s
TRICORE_SRC_EXT := $(TRICORE_EXT)
V850_SRC_EXT := $(V850_EXT)
XTENSA_SRC_EXT := $(XTENSA_EXT)
X86_16_SRC_EXT := $(X86_16_EXT)

# **********************
# *** Rule Templates ***
# **********************

# Assembly template
# Builds .bin and .elf files from assembly source

define ASM_TEMPLATE

$(1)_ASM_BIN_SRCS := $$(filter-out $$($(1)_SRC_EXCLUDE),$$(wildcard */*.$$($(1)_SRC_EXT).s))
$(1)_ASM_ELF_SRCS := $$(wildcard */*.$$($(1)_SRC_EXT).elf.s)

$(1)_ASM_BINS := $$(patsubst %.$$($(1)_SRC_EXT).s,%.$$($(1)_EXT).bin,$$($(1)_ASM_BIN_SRCS))
$(1)_ASM_ELFS := $$(patsubst %.$$($(1)_SRC_EXT).elf.s,%.$$($(1)_EXT).elf,$$($(1)_ASM_ELF_SRCS))

%.$$($(1)_EXT).elf : %.$$($(1)_SRC_EXT).elf.s
	$$($(1)_ELF_AS) $$(GENERAL_ASFLAGS) $$($(1)_ASFLAGS) $$< -femit-bin=$$@

%.$$($(1)_EXT).bin : %.$$($(1)_SRC_EXT).s
	$$($(1)_ASM_AS) $$(GENERAL_ASFLAGS) $$($(1)_ASFLAGS) $$< -femit-bin=$$*.$$($(1)_EXT).o
	$$($(1)_OBJCOPY) $$(GENERAL_OBJCOPYFLAGS) $$($(1)_OBJCOPYFLAGS) -O binary -j .text $$*.$$($(1)_EXT).o $$@
	rm $$*.$$($(1)_EXT).o

endef

# Linux C template
# Builds .elf and .so files from C source

# Excludes the gnu2 objects below, for the same reason as C_SO_SRCS.
C_OBJ_SRCS := $(filter-out %.gnu2.o.c,$(wildcard */*.o.c) $(wildcard */*/*.o.c))
C_ELF_SRCS := $(wildcard */*.elf.c) $(wildcard */*/*.elf.c)
# Excludes the gnu2 sources below: they build through their own rule, with an
# extra flag, and would otherwise match this pattern too.
C_SO_SRCS := $(filter-out %.gnu2.so.c %.gnu.so.c,$(wildcard */*.so.c) $(wildcard */*/*.so.c))

# TLS-descriptor shared objects. Built only for the architectures whose
# relocator and models understand TLS descriptors -- amd64 today; i386 emits
# R_386_TLS_DESC, which I386ElfRelocator does not handle, and there is no i386
# resolver model, so an i386 fixture would be an artifact nothing can load.
# The dialect flag is passed EXPLICITLY rather than relying on the compiler
# default, which differs by toolchain version: a fixture that quietly stopped
# emitting R_X86_64_TLSDESC would keep passing while testing nothing.
C_GNU2_SO_SRCS := $(wildcard */*.gnu2.so.c) $(wildcard */*/*.gnu2.so.c)
# The same, unlinked: a .o carries R_X86_64_GOTPC32_TLSDESC naming a GOT
# slot the linker never got to create, rather than R_X86_64_TLSDESC.
C_GNU2_OBJ_SRCS := $(wildcard */*.gnu2.o.c) $(wildcard */*/*.gnu2.o.c)
# The classic (general-dynamic) dialect, which reaches a thread-local through
# __tls_get_addr. Recent gcc defaults to gnu2, so this too must be asked for
# explicitly to be sure what the fixture contains.
C_GNU_SO_SRCS := $(wildcard */*.gnu.so.c) $(wildcard */*/*.gnu.so.c)
AMD64_GNU_CFLAGS := -mtls-dialect=gnu
AMD64_GNU2_CFLAGS := -mtls-dialect=gnu2

define C_ELF_TEMPLATE

# A platform that can build only some C sources lists its ELF sources in
# $(1)_C_ELF_ONLY, and then builds no objects or shared libraries. A platform
# that can't build some C ELF sources lists them in $(1)_C_ELF_EXCLUDE.
$(1)_C_OBJS := $$(if $$($(1)_C_ELF_ONLY),,$$(patsubst %.o.c,%.$$($(1)_EXT).o,$$(C_OBJ_SRCS)))
$(1)_C_ELFS := $$(patsubst %.elf.c,%.$$($(1)_EXT).elf,$$(filter-out $$($(1)_C_ELF_EXCLUDE),$$(or $$($(1)_C_ELF_ONLY),$$(C_ELF_SRCS))))
$(1)_C_SOS := $$(if $$($(1)_C_ELF_ONLY),,$$(patsubst %.so.c,%.$$($(1)_EXT).so,$$(C_SO_SRCS)))

%.$$($(1)_EXT).o : %.o.c
	$$($(1)_CC) -c $$(GENERAL_CFLAGS) $$($(1)_CFLAGS) -o $$@ $$<

%.$$($(1)_EXT).so : %.so.c $$($(1)_ELF_DEPS)
ifeq ($$($(1)_ELF_LINK_CFLAGS),)
	$$($(1)_CC) $$(GENERAL_CFLAGS) $$($(1)_CFLAGS) -fPIC -shared -o $$@ $$<
else
	$$($(1)_CC) -c $$(GENERAL_CFLAGS) $$($(1)_CFLAGS) -fPIC -o $$@.o $$<
	$$($(1)_CC) $$($(1)_ELF_LINK_CFLAGS) $$($(1)_SO_CFLAGS) -shared -o $$@ $$@.o $$($(1)_ELF_LDLIBS)
	rm $$@.o
endif

$(1)_C_GNU2_OBJS := $$(if $$($(1)_GNU2_CFLAGS),$$(patsubst %.gnu2.o.c,%.gnu2.$$($(1)_EXT).o,$$(C_GNU2_OBJ_SRCS)))

%.gnu2.$$($(1)_EXT).o : %.gnu2.o.c
	$$(if $$($(1)_GNU2_CFLAGS),,$$(error no TLS-descriptor dialect flag for $(1); refusing to build $$@))
	$$($(1)_CC) -c $$(GENERAL_CFLAGS) $$($(1)_CFLAGS) $$($(1)_GNU2_CFLAGS) -fPIC -o $$@ $$<

$(1)_C_GNU2_SOS := $$(if $$($(1)_GNU2_CFLAGS),$$(patsubst %.gnu2.so.c,%.gnu2.$$($(1)_EXT).so,$$(C_GNU2_SO_SRCS)))

# Refuse rather than silently drop the dialect flag: this rule also wins (by
# shortest stem) over the generic %.so rule for an explicitly named target on
# an architecture with no flag, and a fixture built without it would keep
# passing while testing nothing.
%.gnu2.$$($(1)_EXT).so : %.gnu2.so.c
	$$(if $$($(1)_GNU2_CFLAGS),,$$(error no TLS-descriptor dialect flag for $(1); refusing to build $$@))
	$$($(1)_CC) $$(GENERAL_CFLAGS) $$($(1)_CFLAGS) $$($(1)_GNU2_CFLAGS) -fPIC -shared -o $$@ $$<

$(1)_C_GNU_SOS := $$(if $$($(1)_GNU_CFLAGS),$$(patsubst %.gnu.so.c,%.gnu.$$($(1)_EXT).so,$$(C_GNU_SO_SRCS)))

# Refuse rather than silently drop the dialect flag: this rule also wins (by
# shortest stem) over the generic %.so rule for an explicitly named target on
# an architecture with no flag, and a fixture built without it would keep
# passing while testing nothing.
%.gnu.$$($(1)_EXT).so : %.gnu.so.c
	$$(if $$($(1)_GNU_CFLAGS),,$$(error no general-dynamic dialect flag for $(1); refusing to build $$@))
	$$($(1)_CC) $$(GENERAL_CFLAGS) $$($(1)_CFLAGS) $$($(1)_GNU_CFLAGS) -fPIC -shared -o $$@ $$<

# A platform with link flags of its own compiles and links separately.
%.$$($(1)_EXT).elf : %.elf.c $$($(1)_ELF_DEPS)
ifeq ($$($(1)_ELF_LINK_CFLAGS),)
	$$($(1)_CC) $$(GENERAL_CFLAGS) $$($(1)_CFLAGS) $$($(1)_ELF_CFLAGS) -o $$@ $$< $$($(1)_ELF_LDLIBS)
else
	$$($(1)_CC) -c $$(GENERAL_CFLAGS) $$($(1)_CFLAGS) -o $$@.o $$<
	$$($(1)_CC) $$($(1)_ELF_LINK_CFLAGS) $$($(1)_ELF_CFLAGS) -o $$@ $$@.o $$($(1)_ELF_LDLIBS)
	rm $$@.o
endif

endef

# MinGW C template
# Builds .pe and .dll files from C source

C_PE_SRCS := $(wildcard */*.pe.c) $(wildcard */*/*.pe.c)
C_DLL_SRCS := $(wildcard */*.dll.c) $(wildcard */*/*.dll.c)

define C_PE_TEMPLATE

$(1)_C_PES := $$(patsubst %.pe.c,%.$$($(1)_EXT).pe,$$(C_PE_SRCS))
$(1)_C_DLLS := $$(patsubst %.dll.c,%.$$($(1)_EXT).dll,$$(C_DLL_SRCS))

%.$$($(1)_EXT).pe : %.pe.c %.$$($(1)_EXT).dll
	$$($(1)_CC) $$^ -o $$@

%.$$($(1)_EXT).dll : %.dll.c
	$$($(1)_CC) -shared $$< -o $$@

%.$$($(1)_EXT).pe : %.pe.c
	$$($(1)_CC) $$< -o $$@

endef

# 8051 C template
# Builds each .mcs51.c twice with SDCC, once per calling convention, into
# Intel HEX images with the linker's map beside them; see mcs51_cc.sh.

MCS51_C_SRCS := $(wildcard */*.mcs51.c)
MCS51_C_IHXS := $(patsubst %.mcs51.c,%.sdcc.mcs51.ihx,$(MCS51_C_SRCS)) $(patsubst %.mcs51.c,%.sdccstackauto.mcs51.ihx,$(MCS51_C_SRCS))

%.sdcc.mcs51.ihx : %.mcs51.c
	./mcs51_cc.sh $< $@

%.sdccstackauto.mcs51.ihx : %.mcs51.c
	./mcs51_cc.sh --stack-auto $< $@

# libc.mcs51.c once more for a Silicon Labs CIP-51 device, the C8051F330, in
# the medium memory model: its startup code and pdata page through EMI0CN
# rather than P2, and pdata is moved off page 0, so the page matters.
MCS51_C_IHXS += mcs51_sdcc/libc.cip51.mcs51.ihx

mcs51_sdcc/libc.cip51.mcs51.ihx : mcs51_sdcc/libc.mcs51.c
	./mcs51_cc.sh --medium --device C8051F330.h --pdata 0x7e00 $< $@

# And again for the C8051F020, whose EMI0CN is at another address.
MCS51_C_IHXS += mcs51_sdcc/libc.c8051f020.mcs51.ihx

mcs51_sdcc/libc.c8051f020.mcs51.ihx : mcs51_sdcc/libc.mcs51.c
	./mcs51_cc.sh --medium --device C8051F020.h --pdata 0x7e00 $< $@

# And for the C8051F040, which pages its SFRs, and whose EMI0CN is at 0xA2.
MCS51_C_IHXS += mcs51_sdcc/libc.c8051f040.mcs51.ihx

mcs51_sdcc/libc.c8051f040.mcs51.ihx : mcs51_sdcc/libc.mcs51.c
	./mcs51_cc.sh --medium --device C8051F040.h --pdata 0x7e00 $< $@

# sfrpages.c for the devices that page their SFRs as the C8051F040 does.
MCS51_SFRPAGES_DEVICES := c8051f040 c8051f060 c8051f120
MCS51_C_IHXS += $(foreach d,$(MCS51_SFRPAGES_DEVICES),mcs51_sdcc/sfrpages.$(d).mcs51.ihx)

mcs51_sdcc/sfrpages.%.mcs51.ihx : mcs51_sdcc/sfrpages.c
	./mcs51_cc.sh --device $(shell echo $* | tr a-z A-Z).h $< $@

# sfrpages_f36x.c only for the C8051F360, which pages its SFRs its own way.
MCS51_C_IHXS += mcs51_sdcc/sfrpages_f36x.c8051f360.mcs51.ihx

mcs51_sdcc/sfrpages_f36x.c8051f360.mcs51.ihx : mcs51_sdcc/sfrpages_f36x.c
	./mcs51_cc.sh --device C8051F360.h $< $@

# flash.cip51.c only for the C8051F330, whose flash programming it tests.
MCS51_C_IHXS += mcs51_sdcc/flash.cip51.mcs51.ihx

mcs51_sdcc/flash.cip51.mcs51.ihx : mcs51_sdcc/flash.cip51.c
	./mcs51_cc.sh --device C8051F330.h $< $@

# The EFM8BB2, which SDCC has no header for: mcs51_sdcc/efm8bb2.h declares the
# SFRs the programs use.  libc.mcs51.c for it as for the C8051F330, its EMI0CN
# at 0xE7; flash_efm8bb2.c, which erases its two sizes of flash page;
# sfrpages_efm8bb2.c, which reaches SFRs on its pages and reads its page stack;
# and interrupts_efm8bb2.c, which takes its interrupts.
MCS51_EFM8BB2_H := $(CURDIR)/mcs51_sdcc/efm8bb2.h
MCS51_C_IHXS += mcs51_sdcc/libc.efm8bb2.mcs51.ihx mcs51_sdcc/flash_efm8bb2.efm8bb2.mcs51.ihx
MCS51_C_IHXS += mcs51_sdcc/sfrpages_efm8bb2.efm8bb2.mcs51.ihx
MCS51_C_IHXS += mcs51_sdcc/interrupts_efm8bb2.efm8bb2.mcs51.ihx

mcs51_sdcc/libc.efm8bb2.mcs51.ihx : mcs51_sdcc/libc.mcs51.c mcs51_sdcc/efm8bb2.h
	./mcs51_cc.sh --medium --device $(MCS51_EFM8BB2_H) --pdata 0x7e00 $< $@

mcs51_sdcc/flash_efm8bb2.efm8bb2.mcs51.ihx : mcs51_sdcc/flash_efm8bb2.c mcs51_sdcc/efm8bb2.h
	./mcs51_cc.sh --device $(MCS51_EFM8BB2_H) $< $@

mcs51_sdcc/sfrpages_efm8bb2.efm8bb2.mcs51.ihx : mcs51_sdcc/sfrpages_efm8bb2.c mcs51_sdcc/efm8bb2.h
	./mcs51_cc.sh --device $(MCS51_EFM8BB2_H) $< $@

mcs51_sdcc/interrupts_efm8bb2.efm8bb2.mcs51.ihx : mcs51_sdcc/interrupts_efm8bb2.c mcs51_sdcc/efm8bb2.h
	./mcs51_cc.sh --device $(MCS51_EFM8BB2_H) $< $@

# interrupts.cip51.c only for the C8051F330, whose interrupts it tests.
MCS51_C_IHXS += mcs51_sdcc/interrupts.cip51.mcs51.ihx

mcs51_sdcc/interrupts.cip51.mcs51.ihx : mcs51_sdcc/interrupts.cip51.c
	./mcs51_cc.sh --device C8051F330.h $< $@

# The C99 library-model tests whose functions have 8051 models, built the
# same way from their shared sources, and again in SDCC's medium and large
# memory models; see mcs51_cc.sh.  SDCC has no medium-model library for its
# reentrant convention.  Keep in step with _MCS51_FUNCTIONS in
# harness/scenarios/library_models.py.

MCS51_C99_FUNCTIONS := abs atof atoi atol atoll bsearch calloc fabs free getchar gets \
	labs llabs malloc memchr memcmp memcpy memmove memset printf putchar puts qsort \
	rand realloc sprintf srand strcat strchr strcmp strcoll strcpy strcspn \
	strerror strlen strncat strncmp strncpy strpbrk strrchr strspn strstr \
	strtok strxfrm tolower toupper
MCS51_C99_VARIANTS := sdcc sdccstackauto sdcc-medium sdcc-large sdccstackauto-large
MCS51_C_IHXS += $(foreach f,$(MCS51_C99_FUNCTIONS),$(foreach v,$(MCS51_C99_VARIANTS),c99/$(f)/$(f).$(v).mcs51.ihx))

c99/%.sdcc.mcs51.ihx : c99/%.elf.c c99/mcs51_sdcc.h c99/mcs51_sdcc.c
	./mcs51_cc.sh --c99 $< $@

c99/%.sdccstackauto.mcs51.ihx : c99/%.elf.c c99/mcs51_sdcc.h c99/mcs51_sdcc.c
	./mcs51_cc.sh --stack-auto --c99 $< $@

c99/%.sdcc-medium.mcs51.ihx : c99/%.elf.c c99/mcs51_sdcc.h c99/mcs51_sdcc.c
	./mcs51_cc.sh --medium --c99 $< $@

c99/%.sdcc-large.mcs51.ihx : c99/%.elf.c c99/mcs51_sdcc.h c99/mcs51_sdcc.c
	./mcs51_cc.sh --large --c99 $< $@

c99/%.sdccstackauto-large.mcs51.ihx : c99/%.elf.c c99/mcs51_sdcc.h c99/mcs51_sdcc.c
	./mcs51_cc.sh --stack-auto --large --c99 $< $@

# Build phony targets to build everything for the architecture

define GENERAL_TEMPLATE

$(1)_TARGET := $$(call lc,$(1))

.PHONY : $$($(1)_TARGET)
$$($(1)_TARGET) : $$($(1)_ASM_BINS) $$($(1)_C_IHXS) $$($(1)_ASM_ELFS) $$($(1)_ASM_SOS) $$($(1)_C_ELFS) $$($(1)_C_OBJS) $$($(1)_C_GNU2_OBJS) $$($(1)_C_SOS) $$($(1)_C_GNU2_SOS) $$($(1)_C_GNU_SOS) $$($(1)_C_DLLS) $$($(1)_C_PES) 

.PHONY : $$($(1)_TARGET)-clean
$$($(1)_TARGET)-clean :
	find . -name '*.$$($(1)_EXT).o' -type f -delete
	find . -name '*.$$($(1)_EXT).bin' -type f -delete
	find . -name '*.$$($(1)_EXT).ihx' -type f -delete
	find . -name '*.$$($(1)_EXT).map' -type f -delete
	find . -name '*.$$($(1)_EXT).elf' -type f -delete
	find . -name '*.$$($(1)_EXT).so' -type f -delete
	find . -name '*.$$($(1)_EXT).pe' -type f -delete
	find . -name '*.$$($(1)_EXT).dll' -type f -delete

endef 

# *****************************
# *** Actuate the Templates ***
# *****************************

# List of all platforms
PLATFORMS := AARCH64 AARCH64BE AARCH64V85A AARCH64V85ABE AMD64 AMD64_MINGW ARMV4 ARMV4T ARMV5T ARMV4BE ARMV4TBE ARMV5TBE ARMV6K ARMV6M ARMV7A ARMV7EM ARMV7M ARMV7R ARMV8A ARMV8M ARMV8R ARMV6KBE ARMV7ABE ARMV7RBE ARMV8ABE ARMV8RBE I386 I386_MINGW LA64 M68K MIPS MIPSEL MIPS64 MIPS64EL MSP430 MSP430X PPC PPC64 RISCV64 SH4 SH4EL SH2A TRICORE XTENSA LA32 MCS51 MICROMIPS MICROMIPSEL PPCVLE RISCV32 SH2 SH1 V850 X86_16

# List of platforms that support assembly
ASM_PLATFORMS := AARCH64 AARCH64BE AARCH64V85A AARCH64V85ABE AMD64 ARMV4 ARMV4T ARMV5T ARMV4BE ARMV4TBE ARMV5TBE ARMV6K ARMV6M ARMV7A ARMV7EM ARMV7M ARMV7R ARMV8A ARMV8M ARMV8R ARMV6KBE ARMV7ABE ARMV7RBE ARMV8ABE ARMV8RBE I386 LA64 M68K MIPS MIPSEL MIPS64 MIPS64EL MSP430 MSP430X PPC PPC64 RISCV64 SH4 SH4EL SH2A TRICORE XTENSA LA32 MCS51 MICROMIPS MICROMIPSEL PPCVLE RISCV32 SH2 SH1 V850 X86_16

# List of platforms that support ELF
C_ELF_PLATFORMS := AARCH64 AARCH64BE AARCH64V85A AARCH64V85ABE AMD64 ARMV4T ARMV5T ARMV4TBE ARMV5TBE ARMV6K ARMV6M ARMV7A ARMV7EM ARMV7M ARMV7R ARMV8A ARMV8M ARMV8R ARMV6KBE ARMV7ABE ARMV7RBE ARMV8ABE ARMV8RBE I386 LA64 M68K MIPS MIPSEL MIPS64 MIPS64EL PPC PPC64 RISCV64 MICROMIPS MICROMIPSEL RISCV32

# List of platforms that support PE
C_PE_PLATFORMS := AMD64_MINGW I386_MINGW


# Populate the ASM templates
$(foreach platform,$(ASM_PLATFORMS),$(eval $(call ASM_TEMPLATE,$(platform))))

# A microMIPS shared library, and an executable that imports from it, for the
# ELF loader's ISA-bit handling. They are assembly because microMIPS C cannot
# be linked PIC (see MICROMIPS_CFLAGS), and the executable has explicit rules
# because it links against the library.
define MICROMIPS_SO_TEMPLATE

$(1)_ASM_SOS := link_elf/micromips_lib.$$($(1)_EXT).so link_elf/micromips_import.$$($(1)_EXT).elf

link_elf/micromips_lib.$$($(1)_EXT).so : link_elf/micromips_lib.$$($(1)_SRC_EXT).so.s
	$$($(1)_CC) -shared -nostdlib -o $$@ $$<

link_elf/micromips_import.$$($(1)_EXT).elf : link_elf/micromips_import.$$($(1)_SRC_EXT).elf.s link_elf/micromips_lib.$$($(1)_EXT).so
	$$($(1)_CC) -nostdlib -o $$@ $$^

endef

$(foreach platform,MICROMIPS MICROMIPSEL,$(eval $(call MICROMIPS_SO_TEMPLATE,$(platform))))

# Populate the C ELF templates
$(foreach platform,$(C_ELF_PLATFORMS),$(eval $(call C_ELF_TEMPLATE,$(platform))))

# zig's compiler-rt, built for the Cortex-M0. As a freestanding build, it
# leaves out __aeabi_read_tp, which ARMv6-M can't implement as zig does.
# Function sections let the link drop the helpers a test doesn't use.
# -fno-builtin, as zig builds its own compiler-rt: otherwise memset's loop is
# lowered to a call to __aeabi_memset, which calls memset, and recurses.
ZIG_LIB = $(shell zig env | sed -n 's/^ *\.lib_dir = "\(.*\)",$$/\1/p')

compiler_rt.$(ARMV6M_EXT).o :
	zig build-obj $(ZIG_LIB)/compiler_rt.zig -target thumb-freestanding-eabi -mcpu cortex_m0 -O ReleaseSmall -fPIC -ffunction-sections -fno-builtin -femit-bin=$@

# Populate the C PE templates
$(foreach platform,$(C_PE_PLATFORMS),$(eval $(call C_PE_TEMPLATE,$(platform))))

# elf_core runs its binary on a real glibc under qemu-user to get a core dump.
# zig's powerpc64-linux-gnu emits ELFv2 code but binds ELFv1 glibc symbol
# versions (puts@GLIBC_2.3), and ELFv2 glibc starts at GLIBC_2.17, so no glibc
# can load the result.  Nix's ELFv2 cross gcc builds against the glibc
# create_core.sh runs it on.
PPC64_GLIBC_CC := powerpc64-unknown-linux-gnuabielfv2-gcc
elf_core/elf_core.ppc64.elf: PPC64_CC := $(PPC64_GLIBC_CC)
# The test derivation's buildInputs put every cross glibc into
# NIX_CFLAGS_COMPILE and NIX_LDFLAGS, which this gcc reads: it would compile
# against m68k's headers and get an rpath that finds aarch64's libc.so.6
# first.  Its wrapper supplies its own glibc, so drop them.
elf_core/elf_core.ppc64.elf: export NIX_CFLAGS_COMPILE :=
elf_core/elf_core.ppc64.elf: export NIX_LDFLAGS :=

# Populate the general templates
$(foreach platform,$(PLATFORMS),$(eval $(call GENERAL_TEMPLATE,$(platform))))

# sysv again, built as Thumb-2 for ARMv7-A, as armhf distributions build. Its
# functions' symbols carry the Thumb bit, which a model's hook must ignore.
ARMV7A_THUMB_ELFS := sysv/sysv.armv7a_thumb.elf

# zig ignores -mthumb, and has no glibc for a thumb- target, so the source
# (which needs only compiler headers) is compiled freestanding for Thumb, with
# the same AAPCS-VFP ABI, and linked against glibc as ARM.
sysv/sysv.armv7a_thumb.elf : sysv/sysv.elf.c
	zig cc -target thumb-freestanding-eabihf -mcpu=cortex_a9 -fPIC -c $(GENERAL_CFLAGS) -o $@.o $<
	$(ARMV7A_CC) $(ARMV7A_ELF_CFLAGS) -o $@ $@.o
	rm $@.o

armv7a : $(ARMV7A_THUMB_ELFS)

# **********************
# *** Global Targets ***
# **********************

.DEFAULT_GOAL := all
.PHONY : all
all : $(foreach platform,$(PLATFORMS),$(call lc,$(platform)))

.PHONY : clean
clean : 
	find . -name '*.bin' -type f -delete
	find . -name '*.ihx' -type f -delete
	find . -name '*.map' -type f -delete
	find . -name '*.elf' -type f -delete
	find . -name '*.o' -type f -delete
	find . -name '*.so' -type f -delete
	find . -name '*.pe' -type f -delete
	find . -name '*.dll' -type f -delete
	rm -rf tmp/
