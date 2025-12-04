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

AARCH64_ID := aarch64-linux-gnu
AMD64_ID := x86_64-linux-gnu
AMD64_MINGW_ID := x86_64-windows-gnu
ARMEL_ID := arm-linux-gnueabi
ARMHF_ID := arm-linux-gnueabihf
I386_ID := x86-linux-gnu
I386_MINGW_ID := x86-windows-gnu
LA64_ID := loongarch64-linux-gnu
MIPS_ID := mips-linux.1.1.82-gnueabi
MIPSEL_ID := mipsel-linux.1.1.82-gnueabi
MIPS64_ID := mips64-linux-gnuabi64
MIPS64EL_ID := mips64el-linux-gnuabi64
PPC_ID := powerpc-linux.1.3.45-gnueabi
PPC64_ID := powerpc64-linux-gnu
RISCV64_ID := riscv64-linux-gnu
XTENSA_ID := xtensa-lx106-elf

# Assembler Commands for Assembly

AARCH64_ASM_AS := zig build-exe -target $(AARCH64_ID) 
AMD64_ASM_AS := ./nasm_wrapper.sh
ARMEL_ASM_AS := zig build-exe -target $(ARMEL_ID)
ARMHF_ASM_AS := zig build-exe -target $(ARMHF_ID)
I386_ASM_AS := zig build-exe -target $(I386_ID)
LA64_ASM_AS := zig build-exe -target $(LA64_ID)
MIPS_ASM_AS := zig build-exe -target $(MIPS_ID)
MIPSEL_ASM_AS := zig build-exe -target $(MIPSEL_ID)
MIPS64_ASM_AS := zig build-exe -target $(MIPS64_ID)
MIPS64EL_ASM_AS := zig build-exe -target $(MIPS64EL_ID)
PPC_ASM_AS := zig build-exe -target $(PPC_ID)
PPC64_ASM_AS := zig build-exe -target $(PPC64_ID)
RISCV64_ASM_AS := zig build-exe -target $(RISCV64_ID)
XTENSA_ASM_AS := ./xtensa_wrapper.sh

# Assembler Commands for ELF

AARCH64_ELF_AS := zig build-exe -target $(AARCH64_ID) 
AMD64_ELF_AS := zig build-exe -target $(AMD64_ID)
ARMEL_ELF_AS := zig build-exe -target $(ARMEL_ID)
ARMHF_ELF_AS := zig build-exe -target $(ARMHF_ID) 
I386_ELF_AS := zig build-exe -target $(I386_ID) 
LA64_ELF_AS := zig build-exe -target $(LA64_ID) 
MIPS_ELF_AS := zig build-exe -target $(MIPS_ID)
MIPSEL_ELF_AS := zig build-exe -target $(MIPSEL_ID)
MIPS64_ELF_AS := zig build-exe -target $(MIPS64_ID) 
MIPS64EL_ELF_AS := zig build-exe -target $(MIPS64EL_ID) 
PPC_ELF_AS := zig build-exe -target $(PPC_ID)
PPC64_ELF_AS := zig build-exe -target $(PPC64_ID) 
RISCV64_ELF_AS := zig build-exe -target $(RISCV64_ID) 
XTENSA_ELF_AS := ./xtensa_wrapper.sh

# Objcopy Commands

AARCH64_OBJCOPY := zig objcopy
# NASM doesn't produce a .o; we can skip this
AMD64_OBJCOPY := bash -c 'cp -- $$4 $$5'
ARMEL_OBJCOPY := zig objcopy
ARMHF_OBJCOPY := zig objcopy
I386_OBJCOPY := zig objcopy
LA64_OBJCOPY := zig objcopy
MIPS_OBJCOPY := zig objcopy
MIPSEL_OBJCOPY := zig objcopy
MIPS64_OBJCOPY := zig objcopy
MIPS64EL_OBJCOPY := zig objcopy
PPC_OBJCOPY := zig objcopy
PPC64_OBJCOPY := zig objcopy
RISCV64_OBJCOPY := zig objcopy
XTENSA_OBJCOPY := $(XTENSA_ID)-objcopy

# C compiler commands

AARCH64_CC := zig cc -target $(AARCH64_ID) 
AMD64_CC := zig cc -target $(AMD64_ID)  
AMD64_MINGW_CC := zig cc -target $(AMD64_MINGW_ID) 
ARMEL_CC := zig cc -target $(ARMEL_ID)
ARMHF_CC := zig cc -target $(ARMHF_ID) 
I386_CC := zig cc -target $(I386_ID) 
I386_MINGW_CC := zig cc -target $(I386_MINGW_ID) 
LA64_CC := zig cc -target $(LA64_ID) 
MIPS_CC := zig cc -target $(MIPS_ID) 
MIPSEL_CC := zig cc -target $(MIPSEL_ID) 
MIPS64_CC := zig cc -target $(MIPS64_ID) 
MIPS64EL_CC := zig cc -target $(MIPS64EL_ID) 
PPC_CC := zig cc -target $(PPC_ID) 
PPC64_CC := zig cc -target $(PPC64_ID) 
RISCV64_CC := zig cc -target $(RISCV64_ID)
XTENSA_CC := $(XTENSA_ID)-gcc

# *************************
# *** Flag Declarations ***
# *************************

GENERAL_ASFLAGS := $(ASFLAGS)
XTENSA_ASFLAGS := --no-transform --target-align --text-section-literals

# objcopy flags
GENERAL_OBJCOPYFLAGS := $(OBJCOPYFLAGS)

# ld flags
GENERAL_LDFLAGS := $(LDFLAGS)
MIPS64_LDFLAGS := -T mips_linkerscript.ld 
MIPS64EL_LDFLAGS := -T mips_linkerscript.ld 

# C flags
GENERAL_CFLAGS := $(CFLAGS) -g -O0 -fno-sanitize=undefined -fno-stack-protector -fno-builtin -Wno-deprecated-declarations -D_FORTIFY_SOURCE=0 
ARMEL_CFLAGS := -marm -mfloat-abi=soft
ARMHF_CFLAGS := -marm
MIPS64_CFLAGS := -T mips_linkerscript.ld 
MIPS64EL_CFLAGS := -T mips_linkerscript.ld

# ELF Executable C flags
AARCH64_ELF_CFLAGS := -pie
AMD64_ELF_CFLAGS := -pie
ARMHF_ELF_CFLAGS := -pie
I386_ELF_CFLAGS := -pie
PPC64_ELF_CFLAGS := -pie
RISCV64_ELF_CFLAGS := -pie
XTENSA_ELF_CFLAGS := -pie

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
	$$($(1)_ELF_AS) $$(GENERAL_ASFLAGS) $$($(1)_ASFLAGS) $$< -femit-bin=$$@

%.$$($(1)_EXT).bin : %.$$($(1)_SRC_EXT).s
	$$($(1)_ASM_AS) $$(GENERAL_ASFLAGS) $$($(1)_ASFLAGS) $$< -femit-bin=$$*.$$($(1)_EXT).o
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
	$$($(1)_CC) $$(GENERAL_CFLAGS) $$($(1)_CFLAGS) $$($(1)_ELF_CFLAGS) -o $$@ $$<

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
