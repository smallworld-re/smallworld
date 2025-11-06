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

AARCH64_ID := aarch64-unknown-linux-gnu
AMD64_ID := x86_64-linux-gnu
AMD64_MINGW_ID := x86_64-w64-mingw32
ARMEL_ID := arm-linux-gnueabi
ARMHF_ID := arm-linux-gnueabihf
I386_ID := i686-linux-gnu
I386_MINGW_ID := i686-w64-mingw32
LA64_ID := loongarch64-linux-gnu
MIPS_ID := mips-linux-gnu
MIPSEL_ID := mipsel-linux-gnu
MIPS64_ID := mips64-linux-gnuabi64
MIPS64EL_ID := mips64el-linux-gnuabi64
PPC_ID := powerpc-linux-gnu
PPC64_ID := powerpc64-linux-gnu
RISCV64_ID := riscv64-linux-gnu
XTENSA_ID := xtensa-lx106-elf

# Assembler Commands for Assembly

AARCH64_ASM_AS := $(AARCH64_ID)-as 
AMD64_ASM_AS := nasm 
ARMEL_ASM_AS := $(ARMEL_ID)-as 
ARMHF_ASM_AS := $(ARMHF_ID)-as 
I386_ASM_AS := $(I386_ID)-as 
LA64_ASM_AS := $(LA64_ID)-as 
MIPS_ASM_AS := $(MIPS_ID)-as 
MIPSEL_ASM_AS := $(MIPSEL_ID)-as 
MIPS64_ASM_AS := $(MIPS64_ID)-as 
MIPS64EL_ASM_AS := $(MIPS64EL_ID)-as 
PPC_ASM_AS := $(PPC_ID)-as 
PPC64_ASM_AS := $(PPC64_ID)-as 
RISCV64_ASM_AS := $(RISCV64_ID)-as 
XTENSA_ASM_AS := $(XTENSA_ID)-as 

# Assembler Commands for ELF

AARCH64_ELF_AS := $(AARCH64_ID)-as 
AMD64_ELF_AS := $(AMD64_ID)-as
ARMEL_ELF_AS := $(ARMEL_ID)-as 
ARMHF_ELF_AS := $(ARMHF_ID)-as 
I386_ELF_AS := $(I386_ID)-as 
LA64_ELF_AS := $(LA64_ID)-as 
MIPS_ELF_AS := $(MIPS_ID)-as 
MIPSEL_ELF_AS := $(MIPSEL_ID)-as 
MIPS64_ELF_AS := $(MIPS64_ID)-as 
MIPS64EL_ELF_AS := $(MIPS64EL_ID)-as 
PPC_ELF_AS := $(PPC_ID)-as 
PPC64_ELF_AS := $(PPC64_ID)-as 
RISCV64_ELF_AS := $(RISCV64_ID)-as 
XTENSA_ELF_AS := $(XTENSA_ID)-as 

# Objcopy Commands

AARCH64_OBJCOPY := $(AARCH64_ID)-objcopy
# NASM doesn't produce a .o; we can skip this
AMD64_OBJCOPY := bash -c 'cp -- $$4 $$5'
ARMEL_OBJCOPY := $(ARMEL_ID)-objcopy 
ARMHF_OBJCOPY := $(ARMHF_ID)-objcopy 
I386_OBJCOPY := $(I386_ID)-objcopy 
LA64_OBJCOPY := $(LA64_ID)-objcopy 
MIPS_OBJCOPY := $(MIPS_ID)-objcopy 
MIPSEL_OBJCOPY := $(MIPSEL_ID)-objcopy 
MIPS64_OBJCOPY := $(MIPS64_ID)-objcopy 
MIPS64EL_OBJCOPY := $(MIPS64EL_ID)-objcopy 
PPC_OBJCOPY := $(PPC_ID)-objcopy 
PPC64_OBJCOPY := $(PPC64_ID)-objcopy 
RISCV64_OBJCOPY := $(RISCV64_ID)-objcopy 
XTENSA_OBJCOPY := $(XTENSA_ID)-objcopy 

# Linker Commands

AARCH64_LD := $(AARCH64_ID)-ld 
AMD64_LD := $(AMD64_ID)-ld 
ARMEL_LD := $(ARMEL_ID)-ld 
ARMHF_LD := $(ARMHF_ID)-ld 
I386_LD := $(I386_ID)-ld 
LA64_LD := $(LA64_ID)-ld 
MIPS_LD := $(MIPS_ID)-ld 
MIPSEL_LD := $(MIPSEL_ID)-ld 
MIPS64_LD := $(MIPS64_ID)-ld 
MIPS64EL_LD := $(MIPS64EL_ID)-ld 
PPC_LD := $(PPC_ID)-ld 
PPC64_LD := $(PPC64_ID)-ld 
RISCV64_LD := $(RISCV64_ID)-ld 
XTENSA_LD := $(XTENSA_ID)-ld 

# C compiler commands

AARCH64_CC := $(AARCH64_ID)-gcc 
AMD64_CC := $(AMD64_ID)-gcc 
AMD64_MINGW_CC := $(AMD64_MINGW_ID)-gcc 
ARMEL_CC := $(ARMEL_ID)-gcc 
ARMHF_CC := $(ARMHF_ID)-gcc 
I386_CC := $(I386_ID)-gcc 
I386_MINGW_CC := $(I386_MINGW_ID)-gcc 
LA64_CC := $(LA64_ID)-gcc 
MIPS_CC := $(MIPS_ID)-gcc 
MIPSEL_CC := $(MIPSEL_ID)-gcc 
MIPS64_CC := $(MIPS64_ID)-gcc 
MIPS64EL_CC := $(MIPS64EL_ID)-gcc 
PPC_CC := $(PPC_ID)-gcc 
PPC64_CC := $(PPC64_ID)-gcc 
RISCV64_CC := $(RISCV64_ID)-gcc 
XTENSA_CC := $(XTENSA_ID)-gcc

# *************************
# *** Flag Declarations ***
# *************************

# Base address for mips64 and mips64el ELFs
# Panda currently runs binaries in the physical address space.
# mips64 ld uses a starting address that's inside the mips64 MMIO regions.
MIPS64_ELF_START := 0x800000

# as flags
GENERAL_ASFLAGS := $(ASFLAGS)
XTENSA_ASFLAGS := --no-transform --target-align --text-section-literals

# objcopy flags
GENERAL_OBJCOPYFLAGS := $(OBJCOPYFLAGS)

# ld flags
GENERAL_LDFLAGS := $(LDFLAGS)
MIPS64_LDFLAGS := -Ttext-segment=$(MIPS64_ELF_START) 
MIPS64EL_LDFLAGS := -Ttext-segment=$(MIPS64_ELF_START) 

# C flags
GENERAL_CFLAGS := $(CFLAGS) -g -O0 -fno-stack-protector -fno-builtin -Wno-deprecated-declarations -D_FORTIFY_SOURCE=0 
ARMEL_CFLAGS := -marm
ARMHF_CFLAGS := -marm
MIPS64_CFLAGS := -Wl,-Ttext-segment=$(MIPS64_ELF_START) 
MIPS64EL_CFLAGS := -Wl,-Ttext-segment=$(MIPS64_ELF_START)

# ***************************
# *** Template Parameters ***
# ***************************

# Arch-specific extensions.
AARCH64_EXT := aarch64
AMD64_EXT := amd64
AMD64_MINGW_EXT := amd64
ARMEL_EXT := armel
ARMHF_EXT := armhf
I386_EXT := i386
I386_MINGW_EXT := i386
LA64_EXT := la64
MIPS_EXT := mips
MIPSEL_EXT := mipsel
MIPS64_EXT := mips64
MIPS64EL_EXT := mips64el
PPC_EXT := ppc
PPC64_EXT := ppc64
RISCV64_EXT := riscv64
XTENSA_EXT := xtensa

# Arch-specific source extensions
AARCH64_SRC_EXT := $(AARCH64_EXT)
AMD64_SRC_EXT := $(AMD64_EXT)
ARMEL_SRC_EXT := $(ARMEL_EXT)
ARMHF_SRC_EXT := $(ARMHF_EXT)
I386_SRC_EXT := $(I386_EXT)
LA64_SRC_EXT := $(LA64_EXT)
MIPS_SRC_EXT := $(MIPS_EXT)
# NOTE: mipsel uses mips source
MIPSEL_SRC_EXT := $(MIPS_EXT)
MIPS64_SRC_EXT := $(MIPS64_EXT)
# NOTE: mips64el uses mips64 source
MIPS64EL_SRC_EXT := $(MIPS64_EXT)
PPC_SRC_EXT := $(PPC_EXT)
PPC64_SRC_EXT := $(PPC64_EXT)
RISCV64_SRC_EXT := $(RISCV64_EXT)
XTENSA_SRC_EXT := $(XTENSA_EXT)

# **********************
# *** Rule Templates ***
# **********************

# Assembly template
# Builds .bin and .elf files from assembly source

define ASM_TEMPLATE

$(1)_ASM_BIN_SRCS := $$(wildcard */*.$$($(1)_SRC_EXT).s)
$(1)_ASM_ELF_SRCS := $$(wildcard */*.$$($(1)_SRC_EXT).elf.s)

$(1)_ASM_BINS := $$(patsubst %.$$($(1)_SRC_EXT).s,%.$$($(1)_EXT).bin,$$($(1)_ASM_BIN_SRCS))
$(1)_ASM_ELFS := $$(patsubst %.$$($(1)_SRC_EXT).elf.s,%.$$($(1)_EXT).elf,$$($(1)_ASM_ELF_SRCS))

%.$$($(1)_EXT).elf : %.$$($(1)_SRC_EXT).elf.s
	$$($(1)_ELF_AS) $$(GENERAL_ASFLAGS) $$($(1)_ASFLAGS) $$< -o $$*.$$($(1)_EXT).o
	$$($(1)_LD) $$(GENERAL_LDFLAGS) $$($(1)_LDFLAGS) $$*.$$($(1)_EXT).o -o $$@
	rm $$*.$$($(1)_EXT).o

%.$$($(1)_EXT).bin : %.$$($(1)_SRC_EXT).s
	$$($(1)_ASM_AS) $$(GENERAL_ASFLAGS) $$($(1)_ASFLAGS) $$< -o $$*.$$($(1)_EXT).o
	$$($(1)_OBJCOPY) $$(GENERAL_OBJCOPYFLAGS) $$($(1)_OBJCOPYFLAGS) -O binary -j .text $$*.$$($(1)_EXT).o $$@
	rm $$*.$$($(1)_EXT).o

endef

# Linux C template
# Builds .elf and .so files from C source

C_ELF_SRCS := $(wildcard */*.elf.c) $(wildcard */*/*.elf.c)
C_SO_SRCS := $(wildcard */*.so.c) $(wildcard */*/*.so.c)

define C_ELF_TEMPLATE

$(1)_C_ELFS := $$(patsubst %.elf.c,%.$$($(1)_EXT).elf,$$(C_ELF_SRCS))
$(1)_C_SOS := $$(patsubst %.so.c,%.$$($(1)_EXT).so,$$(C_SO_SRCS))

%.$$($(1)_EXT).so : %.so.c
	$$($(1)_CC) $$(GENERAL_CFLAGS) $$($(1)_CFLAGS) -shared -o $$@ $$<

%.$$($(1)_EXT).elf : %.elf.c
	$$($(1)_CC) $$(GENERAL_CFLAGS) $$($(1)_CFLAGS) -o $$@ $$<

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

# Build phony targets to build everything for the architecture

define GENERAL_TEMPLATE

$(1)_TARGET := $$(call lc,$(1))

.PHONY : $$($(1)_TARGET)
$$($(1)_TARGET) : $$($(1)_ASM_BINS) $$($(1)_ASM_ELFS) $$($(1)_C_ELFS) $$($(1)_C_SOS) $$($(1)_C_DLLS) $$($(1)_C_PES) 

.PHONY : $$($(1)_TARGET)-clean
$$($(1)_TARGET)-clean :
	find . -name '*.$$($(1)_EXT).o' -type f -delete
	find . -name '*.$$($(1)_EXT).bin' -type f -delete
	find . -name '*.$$($(1)_EXT).elf' -type f -delete
	find . -name '*.$$($(1)_EXT).so' -type f -delete
	find . -name '*.$$($(1)_EXT).pe' -type f -delete
	find . -name '*.$$($(1)_EXT).dll' -type f -delete

endef 

# *****************************
# *** Actuate the Templates ***
# *****************************

# List of all platforms
PLATFORMS := AARCH64 AMD64 AMD64_MINGW ARMEL ARMHF I386 I386_MINGW LA64 MIPS MIPSEL MIPS64 MIPS64EL PPC PPC64 RISCV64 XTENSA

# List of platforms that support assembly
ASM_PLATFORMS := AARCH64 AMD64 ARMEL ARMHF I386 LA64 MIPS MIPSEL MIPS64 MIPS64EL PPC PPC64 RISCV64 XTENSA

# List of platforms that support ELF
C_ELF_PLATFORMS := AARCH64 AMD64 ARMEL ARMHF I386 LA64 MIPS MIPSEL MIPS64 MIPS64EL PPC PPC64 RISCV64

# List of platforms that support PE
C_PE_PLATFORMS := AMD64_MINGW I386_MINGW


# Populate the ASM templates
$(foreach platform,$(ASM_PLATFORMS),$(eval $(call ASM_TEMPLATE,$(platform))))

# Populate the C ELF templates
$(foreach platform,$(C_ELF_PLATFORMS),$(eval $(call C_ELF_TEMPLATE,$(platform))))

# Populate the C PE templates
$(foreach platform,$(C_PE_PLATFORMS),$(eval $(call C_PE_TEMPLATE,$(platform))))

# Populate the general templates
$(foreach platform,$(PLATFORMS),$(eval $(call GENERAL_TEMPLATE,$(platform))))

# **********************
# *** Global Targets ***
# **********************

.DEFAULT_GOAL := all
.PHONY : all
all : $(foreach platform,$(PLATFORMS),$(call lc,$(platform)))

.PHONY : clean
clean : 
	find . -name '*.bin' -type f -delete
	find . -name '*.elf' -type f -delete
	find . -name '*.o' -type f -delete
	find . -name '*.so' -type f -delete
	find . -name '*.pe' -type f -delete
	find . -name '*.dll' -type f -delete
