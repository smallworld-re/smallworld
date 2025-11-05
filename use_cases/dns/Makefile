# String to-lower macro
lc = $(subst A,a,$(subst B,b,$(subst C,c,$(subst D,d,$(subst E,e,$(subst F,f,$(subst G,g,$(subst H,h,$(subst I,i,$(subst J,j,$(subst K,k,$(subst L,l,$(subst M,m,$(subst N,n,$(subst O,o,$(subst P,p,$(subst Q,q,$(subst R,r,$(subst S,s,$(subst T,t,$(subst U,u,$(subst V,v,$(subst W,w,$(subst X,x,$(subst Y,y,$(subst Z,z,$1))))))))))))))))))))))))))

# Source and include search paths and files
vpath %.c src/
vpath %.h include/
HDRS = $(wildcard include/*.h)
SRCS = $(wildcard src/*.c)

# C compiler; we're using clang
CC = clang-14

# Universal cflags 
INCLUDES = -I ./include
GEN_CFLAGS = -O0 -Wall -Wextra -Werror -g

# Optional fuzzing configs; only works for amd64
ifdef FUZZ
SAN_CFLAGS = -fsanitize=fuzzer-no-link,address
FUZZ_CFLAGS = -fsanitize=fuzzer,address
endif

ifdef DEBUG
DEBUG_CFLAGS = -DDEBUG
endif

ALL_CFLAGS = $(CFLAGS) $(GEN_CFLAGS) $(DEBUG_CFLAGS) $(INCLUDES) $(SAN_CFLAGS)

# List of platforms 
PLATFORMS = AARCH64 AMD64 ARMEL ARMHF I386 MIPS MIPSEL MIPS64 MIPS64EL PPC

# Platform-specific clang target
AARCH64_TARGET = --target=aarch64-unknown-linux-gnu
AMD64_TARGET =
ARMEL_TARGET = --target=arm-linux-gnueabi
ARMHF_TARGET = --target=arm-linux-gnueabihf
I386_TARGET = --target=i686-linux-gnu
MIPS_TARGET = --target=mips-linux-gnu
MIPSEL_TARGET = --target=mipsel-linux-gnu
MIPS64_TARGET = --target=mips64-linux-gnuabi64
MIPS64EL_TARGET = --target=mips64el-linux-gnuabi64
PPC_TARGET = --target=powerpc-linux-gnu

# Platform-specific linker
# Selecting a target for clang doesn't select
# a target-appropriate linker toolchain; it always uses gcc.
AMD64_LINK = gcc 
AARCH64_LINK = aarch64-unknown-linux-gnu-gcc
ARMEL_LINK = arm-linux-gnueabi-gcc
ARMHF_LINK = arm-linux-gnueabihf-gcc
I386_LINK = i686-linux-gnu-gcc
MIPS_LINK = mips-linux-gnu-gcc
MIPSEL_LINK = mipsel-linux-gnu-gcc
MIPS64_LINK = mips64-linux-gnuabi64-gcc
MIPS64EL_LINK = mips64el-linux-gnuabi64-gcc
PPC_LINK = powerpc-linux-gnu-gcc

# Platform-specific file lists and build target template
define ARCH_TEMPLATE
$(1)_EXT = $$(call lc,$(1))
$(1)_OBJS = $$(patsubst src/%.c,%.$$($(1)_EXT).o,$$(SRCS))
$(1)_ELFS = $$(patsubst src/%.elf.c,bin/%.$$($(1)_EXT).elf,$$(wildcard src/*.elf.c))

$(1)_LIB_OBJS = $$(filter-out %.elf.$$($(1)_EXT).o,$$(filter-out %.fuzz.o,$$($(1)_OBJS)))
$(1)_LIB = lib/libfakedns.$$($(1)_EXT).a

bin/%.$$($(1)_EXT).elf : %.elf.$$($(1)_EXT).o $$($(1)_LIB) | bin
	$$($(1)_LINK) $$(ALL_CFLAGS) $$< $$($(1)_LIB) -o $$@

lib/%.$$($(1)_EXT).a : $$($(1)_LIB_OBJS) | lib
	$$(AR) -rcs $$@ $$^

%.$$($(1)_EXT).o : %.c $(HDRS)
	$$(CC) $$($(1)_TARGET) $$(ALL_CFLAGS) -c $$< -o $$@

.PHONY : all.$(1)
all.$(1) : $$($(1)_LIB) $$($(1)_ELFS)

endef 

# Expand arch-specific template for each platform
$(foreach platform,$(PLATFORMS),$(eval $(call ARCH_TEMPLATE,$(platform))))

# Define fuzzing targets
ifdef FUZZ
FUZZ_ELFS = $(patsubst src/%.fuzz.c,%.fuzz,$(wildcard src/*.fuzz.c))

%.fuzz : %.fuzz.amd64.o $(AMD64_LIB)
	$(FUZZ_CC) $(ALL_CFLAGS) $(FUZZ_CFLAGS) $< $(AMD64_LIB) -o $@

endif

# Define directory-building targets
bin :
	mkdir -p $@

lib :
	mkdir -p $@

# Define global goal for fuzzing
# needs to always be defined so "all" doesn't get mad.
.PHONY : all.FUZZ
all.FUZZ : $(FUZZ_ELFS)

# Collect "all" targets for all platforms
ARCH_ALLS = $(foreach platform,$(PLATFORMS),all.$(platform))

.DEFAULT_GOAL := all
.PHONY : all
all : $(ARCH_ALLS) all.FUZZ

.PHONY : clean
clean :
	rm -f *.o bin/*.elf bin/*.fuzz lib/*.a	
