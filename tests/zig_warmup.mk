# Pre-populate zig's global cache (ZIG_GLOBAL_CACHE_DIR) with the per-target
# runtime libraries (glibc/mingw stubs, CRT files, compiler-rt) that the test
# build links against, without compiling any of the tests.
#
# zig builds those libraries on first use of each target and link mode, which
# is most of the cold build time. This file reuses the Makefile's own
# per-platform commands and flags, so the cache keys match the real build;
# only the source file is replaced by a stub. Each warm-up is best effort: a
# miss just means the real build compiles that library itself.
#
# Usage: make -f zig_warmup.mk -j<N>

include Makefile

.DEFAULT_GOAL := zig-warmup

WARM := zig-warmup.d

is_zig = $(filter zig,$(firstword $(1)))

ZIG_C_ELF := $(foreach p,$(C_ELF_PLATFORMS),$(if $(call is_zig,$($(p)_CC)),$(p)))
ZIG_C_PE := $(foreach p,$(C_PE_PLATFORMS),$(if $(call is_zig,$($(p)_CC)),$(p)))
ZIG_ASM := $(foreach p,$(ASM_PLATFORMS),$(if $(call is_zig,$($(p)_ASM_AS)),$(p)))
ZIG_ELF_AS := $(foreach p,$(ASM_PLATFORMS),$(if $(call is_zig,$($(p)_ELF_AS)),$(p)))
ZIG_ASM_SO := $(foreach p,$(PLATFORMS),$(if $($(p)_ASM_SOS),$(if $(call is_zig,$($(p)_CC)),$(p))))

$(WARM)/stub.c :
	mkdir -p $(WARM)
	printf 'int main(void) { return 0; }\n' > $@

$(WARM)/stub.s :
	mkdir -p $(WARM)
	printf '.globl _start\n_start:\n' > $@

# Mirrors C_ELF_TEMPLATE: executables, shared objects (plain and with each
# TLS dialect; not for -fno-pic platforms, which have no C shared objects).
# `-c` objects link nothing, so they are skipped.
define WARM_C_ELF
warm-$(1)-exe : $(WARM)/stub.c
	-$$($(1)_CC) $$(GENERAL_CFLAGS) $$($(1)_CFLAGS) $$($(1)_ELF_CFLAGS) -o $(WARM)/$(1).elf $$< $$($(1)_ELF_LDLIBS)
warm-$(1)-so : $(WARM)/stub.c
	-$$($(1)_CC) $$(GENERAL_CFLAGS) $$($(1)_CFLAGS) -fPIC -shared -o $(WARM)/$(1).so $$<
	$$(if $$($(1)_GNU_CFLAGS),-$$($(1)_CC) $$(GENERAL_CFLAGS) $$($(1)_CFLAGS) $$($(1)_GNU_CFLAGS) -fPIC -shared -o $(WARM)/$(1).gnu.so $$<)
	$$(if $$($(1)_GNU2_CFLAGS),-$$($(1)_CC) $$(GENERAL_CFLAGS) $$($(1)_CFLAGS) $$($(1)_GNU2_CFLAGS) -fPIC -shared -o $(WARM)/$(1).gnu2.so $$<)
ZIG_WARM_TARGETS += warm-$(1)-exe $(if $(filter -fno-pic,$($(1)_CFLAGS)),,warm-$(1)-so)
endef

# Mirrors C_PE_TEMPLATE.
define WARM_C_PE
warm-$(1)-pe : $(WARM)/stub.c
	-$$($(1)_CC) $$< -o $(WARM)/$(1).pe
warm-$(1)-dll : $(WARM)/stub.c
	-$$($(1)_CC) -shared $$< -o $(WARM)/$(1).dll
ZIG_WARM_TARGETS += warm-$(1)-pe warm-$(1)-dll
endef

# Mirrors ASM_TEMPLATE. zig also builds its own objcopy on first use.
define WARM_ASM
warm-$(1)-asm : $(WARM)/stub.s
	-$$($(1)_ASM_AS) $$(GENERAL_ASFLAGS) $$($(1)_ASFLAGS) $$< -femit-bin=$(WARM)/$(1).asm.o
	$$(if $$(call is_zig,$$($(1)_OBJCOPY)),-$$($(1)_OBJCOPY) $$(GENERAL_OBJCOPYFLAGS) $$($(1)_OBJCOPYFLAGS) -O binary -j .text $(WARM)/$(1).asm.o $(WARM)/$(1).asm.bin)
ZIG_WARM_TARGETS += warm-$(1)-asm
endef

define WARM_ELF_AS
warm-$(1)-elfas : $(WARM)/stub.s
	-$$($(1)_ELF_AS) $$(GENERAL_ASFLAGS) $$($(1)_ASFLAGS) $$< -femit-bin=$(WARM)/$(1).elfas.elf
ZIG_WARM_TARGETS += warm-$(1)-elfas
endef

# Mirrors MICROMIPS_SO_TEMPLATE: assembly linked with -nostdlib.
define WARM_ASM_SO
warm-$(1)-asmso : $(WARM)/stub.s
	-$$($(1)_CC) -shared -nostdlib -o $(WARM)/$(1).asmso.so $$<
	-$$($(1)_CC) -nostdlib -o $(WARM)/$(1).asmso.elf $$<
ZIG_WARM_TARGETS += warm-$(1)-asmso
endef

$(foreach p,$(ZIG_C_ELF),$(eval $(call WARM_C_ELF,$(p))))
$(foreach p,$(ZIG_C_PE),$(eval $(call WARM_C_PE,$(p))))
$(foreach p,$(ZIG_ASM),$(eval $(call WARM_ASM,$(p))))
$(foreach p,$(ZIG_ELF_AS),$(eval $(call WARM_ELF_AS,$(p))))
$(foreach p,$(ZIG_ASM_SO),$(eval $(call WARM_ASM_SO,$(p))))

.PHONY : zig-warmup $(ZIG_WARM_TARGETS)
zig-warmup : $(ZIG_WARM_TARGETS)
