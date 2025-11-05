.PHONY: all build clean check
.DEFAULT_GOAL=all

SOURCES := $(wildcard */*.s) $(wildcard */*/*.s)
BINSOURCES := $(filter-out %.elf.s,$(SOURCES))
ELFSOURCES := $(filter %.elf.s,$(SOURCES))

CSOURCES := $(wildcard */*.c) $(wildcard */*/*.c)
CELFSOURCES := $(filter %.elf.c,$(CSOURCES))
CSOSOURCES := $(filter %.so.c,$(CSOURCES))
CPESOURCES := $(filter %.pe.c,$(CSOURCES))
CDLLSOURCES := $(filter %.dll.c,$(CSOURCES))

BINS := $(patsubst %.s,%.bin,$(BINSOURCES))
ELFS := $(patsubst %.s,%,$(ELFSOURCES))

CELFS := $(patsubst %.elf.c,%.aarch64.elf,$(CELFSOURCES)) $(patsubst %.elf.c,%.amd64.elf,$(CELFSOURCES)) $(patsubst %.elf.c,%.armel.elf,$(CELFSOURCES)) $(patsubst %.elf.c,%.armhf.elf,$(CELFSOURCES)) $(patsubst %.elf.c,%.i386.elf,$(CELFSOURCES)) $(patsubst %.elf.c,%.la64.elf,$(CELFSOURCES)) $(patsubst %.elf.c,%.mips.elf,$(CELFSOURCES)) $(patsubst %.elf.c,%.mipsel.elf,$(CELFSOURCES)) $(patsubst %.elf.c,%.mips64.elf,$(CELFSOURCES)) $(patsubst %.elf.c,%.mips64el.elf,$(CELFSOURCES)) $(patsubst %.elf.c,%.ppc.elf,$(CELFSOURCES)) $(patsubst %.elf.c,%.ppc64.elf,$(CELFSOURCES)) $(patsubst %.elf.c,%.riscv64.elf,$(CELFSOURCES))
CSOS := $(patsubst %.so.c,%.aarch64.so,$(CSOSOURCES)) $(patsubst %.so.c,%.amd64.so,$(CSOSOURCES)) $(patsubst %.so.c,%.armel.so,$(CSOSOURCES)) $(patsubst %.so.c,%.armhf.so,$(CSOSOURCES)) $(patsubst %.so.c,%.i386.so,$(CSOSOURCES)) $(patsubst %.so.c,%.la64.so,$(CSOSOURCES)) $(patsubst %.so.c,%.mips.so,$(CSOSOURCES)) $(patsubst %.so.c,%.mipsel.so,$(CSOSOURCES)) $(patsubst %.so.c,%.mips64.so,$(CSOSOURCES)) $(patsubst %.so.c,%.mips64el.so,$(CSOSOURCES)) $(patsubst %.so.c,%.ppc.so,$(CSOSOURCES)) $(patsubst %.so.c,%.ppc64.so,$(CSOSOURCES)) $(patsubst %.so.c,%.riscv64.so,$(CSOSOURCES))
CPES := $(patsubst %.pe.c,%.amd64.pe,$(CPESOURCES)) $(patsubst %.pe.c,%.i386.pe,$(CPESOURCES))
CDLLS := $(patsubst %.dll.c,%.amd64.dll,$(CDLLSOURCES)) $(patsubst %.dll.c,%.i386.dll,$(CDLLSOURCES))

MIPSEL_BINS := $(patsubst %.mips.bin,%.mipsel.bin,$(filter %.mips.bin,$(BINS)))
MIPSEL_ELFS := $(patsubst %.mips.elf,%.mipsel.elf,$(filter %.mips.elf,$(ELFS)))
MIPS64EL_BINS := $(patsubst %.mips64.bin,%.mips64el.bin,$(filter %.mips64.bin,$(BINS)))
MIPS64EL_ELFS := $(patsubst %.mips64.elf,%.mips64el.elf,$(filter %.mips64.elf,$(ELFS)))
TARGETS := $(BINS) $(MIPSEL_BINS) $(MIPS64EL_BINS) $(ELFS) $(MIPSEL_ELFS) $(MIPS64EL_ELFS) $(CELFS) $(CSOS) $(CDLLS) $(CPES)

NASM_SOURCES := $(wildcard *.amd64.s)
NASM_TARGETS := $(NASM_SOURCES:.s=.bin)

PREREQS := $(patsubst %,%.prereq,aarch64-unknown-linux-gnu arm-linux-gnueabi arm-linux-gnueabihf mips-linux-gnu mipsel-linux-gnu mips64-linux-gnuabi64 mips64el-linux-gnuabi64 powerpc-linux-gnu powerpc64-linux-gnu riscv64-linux-gnu xtensa-lx106-elf)

GENERAL_CFLAGS := $(CFLAGS) -g -O0 -fno-stack-protector -fno-builtin -Wno-deprecated-declarations

# Custom start offset for MIPS64 and MIPS64EL
# Panda currently runs binaries in the physical address space.
# mips64 GCC uses a starting address that's inside
# the mips64 MMIO regions.
MIPS64_ELF_START=0x800000

ifdef LOONGARCH_SYSROOT
    LOONGARCH64_CFLAGS=--sysroot $(LOONGARCH64_SYSROOT)
endif

%.aarch64.so: %.so.c
	aarch64-unknown-linux-gnu-gcc $(GENERAL_CFLAGS) $*.so.c -shared -o $*.aarch64.so

%.aarch64.elf: %.elf.c
	aarch64-unknown-linux-gnu-gcc $(GENERAL_CFLAGS) $*.elf.c -o $*.aarch64.elf

%.aarch64.elf: %.aarch64.elf.s
	aarch64-unknown-linux-gnu-as $*.aarch64.elf.s -o $*.aarch64.elf.o
	aarch64-unknown-linux-gnu-ld $*.aarch64.elf.o -o $*.aarch64.elf
	rm $*.aarch64.elf.o

%.aarch64.bin: %.aarch64.s
	aarch64-unknown-linux-gnu-as $*.aarch64.s -o $*.aarch64.o
	aarch64-unknown-linux-gnu-objcopy -O binary -j .text $*.aarch64.o $*.aarch64.bin
	rm $*.aarch64.o

%.amd64.so: %.so.c
	gcc $(GENERAL_CFLAGS) $*.so.c -shared -o $*.amd64.so

%.amd64.elf: %.elf.c
	gcc $(GENERAL_CFLAGS) $*.elf.c -o $*.amd64.elf

%.amd64.pe: %.pe.c %.amd64.dll
	x86_64-w64-mingw32-gcc $*.pe.c $*.amd64.dll -o $*.amd64.pe

%.amd64.pe: %.pe.c
	x86_64-w64-mingw32-gcc $*.pe.c -o $*.amd64.pe


%.amd64.dll: %.dll.c
	x86_64-w64-mingw32-gcc -shared $*.dll.c -o $*.amd64.dll

%.amd64.elf: %.amd64.elf.s
	as $*.amd64.elf.s -o $*.amd64.elf.o
	ld $*.amd64.elf.o -o $*.amd64.elf
	rm $*.amd64.elf.o

%.amd64.bin: %.amd64.s
	nasm $*.amd64.s -o $*.amd64.bin

%.armel.so: %.so.c
	arm-linux-gnueabi-gcc $(GENERAL_CFLAGS) -marm $*.so.c -shared -o $*.armel.so

%.armel.elf: %.elf.c
	arm-linux-gnueabi-gcc $(GENERAL_CFLAGS) -marm $*.elf.c -o $*.armel.elf

%.armel.elf: %.armel.elf.s
	arm-linux-gnueabi-as $*.armel.elf.s -o $*.armel.elf.o
	arm-linux-gnueabi-ld $*.armel.elf.o -o $*.armel.elf
	rm $*.armel.elf.o

%.armel.bin: %.armel.s
	arm-linux-gnueabi-as $*.armel.s -o $*.armel.o
	arm-linux-gnueabi-objcopy -O binary -j .text $*.armel.o $*.armel.bin
	rm $*.armel.o

%.armhf.so: %.so.c
	arm-linux-gnueabihf-gcc $(GENERAL_CFLAGS) -marm $*.so.c -shared -o $*.armhf.so

%.armhf.elf: %.elf.c
	arm-linux-gnueabihf-gcc $(GENERAL_CFLAGS) -marm $*.elf.c -o $*.armhf.elf

%.armhf.elf: %.armhf.elf.s
	arm-linux-gnueabihf-as $*.armhf.elf.s -o $*.armhf.elf.o
	arm-linux-gnueabihf-ld $*.armhf.elf.o -o $*.armhf.elf
	rm $*.armhf.elf.o

%.armhf.bin: %.armhf.s
	arm-linux-gnueabihf-as $*.armhf.s -o $*.armhf.o
	arm-linux-gnueabihf-objcopy -O binary -j .text $*.armhf.o $*.armhf.bin
	rm $*.armhf.o

%.i386.so: %.so.c
	i686-linux-gnu-gcc $(GENERAL_CFLAGS) $*.so.c -shared -o $*.i386.so

%.i386.elf: %.elf.c
	i686-linux-gnu-gcc $(GENERAL_CFLAGS) $*.elf.c -o $*.i386.elf

%.i386.pe: %.pe.c %.i386.dll
	i686-w64-mingw32-gcc $*.pe.c $*.i386.dll -o $*.i386.pe

%.i386.dll: %.dll.c
	i686-w64-mingw32-gcc -shared $*.dll.c -o $*.i386.dll

%.i386.pe: %.pe.c
	i686-w64-mingw32-gcc $*.pe.c -o $*.i386.pe

%.i386.elf: %.i386.elf.s
	i686-linux-gnu-as $*.i386.elf.s -o $*.i386.elf.o
	i686-linux-gnu-ld $*.i386.elf.o -o $*.i386.elf
	rm $*.i386.elf.o

%.i386.bin: %.i386.s
	i686-linux-gnu-as $*.i386.s -o $*.i386.o
	i686-linux-gnu-objcopy -O binary -j .text $*.i386.o $*.i386.bin
	rm $*.i386.o

%.la64.so: %.so.c
	loongarch64-linux-gnu-gcc $(GENERAL_CFLAGS) $(LOONGARCH64_CFLAGS) $*.so.c -shared -o $*.la64.so

%.la64.elf: %.elf.c
	loongarch64-linux-gnu-gcc $(GENERAL_CFLAGS) $(LOONGARCH64_CFLAGS) $*.elf.c -o $*.la64.elf

%.la64.elf: %.la64.elf.s
	loongarch64-linux-gnu-as $*.la64.elf.s -o $*.la64.elf.o
	loongarch64-linux-gnu-ld $*.la64.elf.o -o $*.la64.elf
	rm $*.la64.elf.o

%.la64.bin: %.la64.s
	loongarch64-linux-gnu-as $*.la64.s -o $*.la64.o
	loongarch64-linux-gnu-objcopy -O binary -j .text $*.la64.o $*.la64.bin
	rm $*.la64.o

%.mips.so: %.so.c
	mips-linux-gnu-gcc $(GENERAL_CFLAGS) $*.so.c -shared -o $*.mips.so

%.mips.elf: %.elf.c
	mips-linux-gnu-gcc $(GENERAL_CFLAGS) $*.elf.c -o $*.mips.elf

%.mips.elf: %.mips.elf.s
	mips-linux-gnu-as $*.mips.elf.s -o $*.mips.elf.o
	mips-linux-gnu-ld $*.mips.elf.o -o $*.mips.elf
	rm $*.mips.elf.o

%.mips.bin: %.mips.s
	mips-linux-gnu-as $*.mips.s -o $*.mips.o
	mips-linux-gnu-objcopy -O binary -j .text $*.mips.o $*.mips.bin
	rm $*.mips.o

%.mipsel.so: %.so.c
	mipsel-linux-gnu-gcc $(GENERAL_CFLAGS) $*.so.c -shared -o $*.mipsel.so

%.mipsel.elf: %.elf.c
	mipsel-linux-gnu-gcc $(GENERAL_CFLAGS) $*.elf.c -o $*.mipsel.elf

%.mipsel.elf: %.mips.elf.s
	mipsel-linux-gnu-as $*.mips.elf.s -o $*.mipsel.elf.o
	mipsel-linux-gnu-ld $*.mipsel.elf.o -o $*.mipsel.elf
	rm $*.mipsel.elf.o

%.mipsel.bin: %.mips.s
	mipsel-linux-gnu-as $*.mips.s -o $*.mipsel.o
	mipsel-linux-gnu-objcopy -O binary -j .text $*.mipsel.o $*.mipsel.bin
	rm $*.mipsel.o

%.mips64.so: %.so.c
	mips64-linux-gnuabi64-gcc $(GENERAL_CFLAGS) $*.so.c -shared -o $*.mips64.so

%.mips64.elf: %.elf.c
	mips64-linux-gnuabi64-gcc $(GENERAL_CFLAGS) -Wl,-Ttext-segment=$(MIPS64_ELF_START) $*.elf.c -o $*.mips64.elf

%.mips64.elf: %.mips64.elf.s
	mips64-linux-gnuabi64-as $*.mips64.elf.s -o $*.mips64.elf.o
	mips64-linux-gnuabi64-ld -Ttext-segment=$(MIPS64_ELF_START) $*.mips64.elf.o -o $*.mips64.elf
	rm $*.mips64.elf.o

%.mips64.bin: %.mips64.s
	mips64-linux-gnuabi64-as $*.mips64.s -o $*.mips64.o
	mips64-linux-gnuabi64-objcopy -O binary -j .text $*.mips64.o $*.mips64.bin
	rm $*.mips64.o

%.mips64el.so: %.so.c
	mips64el-linux-gnuabi64-gcc $(GENERAL_CFLAGS) $*.so.c -shared -o $*.mips64el.so

%.mips64el.elf: %.elf.c
	mips64el-linux-gnuabi64-gcc $(GENERAL_CFLAGS) -Wl,-Ttext-segment=$(MIPS64_ELF_START) $*.elf.c -o $*.mips64el.elf

%.mips64el.elf: %.mips64.elf.s
	mips64el-linux-gnuabi64-as $*.mips64.elf.s -o $*.mips64el.elf.o
	mips64el-linux-gnuabi64-ld -Ttext-segment=$(MIPS64_ELF_START) $*.mips64el.elf.o -o $*.mips64el.elf
	rm $*.mips64el.elf.o

%.mips64el.bin: %.mips64.s
	mips64el-linux-gnuabi64-as $*.mips64.s -o $*.mips64el.o
	mips64el-linux-gnuabi64-objcopy -O binary -j .text $*.mips64el.o $*.mips64el.bin
	rm $*.mips64el.o

%.ppc.so: %.so.c
	powerpc-linux-gnu-gcc $(GENERAL_CFLAGS) $*.so.c -shared -o $*.ppc.so

%.ppc.elf: %.elf.c
	powerpc-linux-gnu-gcc $(GENERAL_CFLAGS) $*.elf.c -o $*.ppc.elf

%.ppc.elf: %.ppc.elf.s
	powerpc-linux-gnu-as $*.ppc.elf.s -o $*.ppc.elf.o
	powerpc-linux-gnu-ld $*.ppc.elf.o -o $*.ppc.elf
	rm $*.ppc.elf.o

%.ppc.bin: %.ppc.s
	powerpc-linux-gnu-as $*.ppc.s -o $*.ppc.o
	powerpc-linux-gnu-objcopy -O binary -j .text $*.ppc.o $*.ppc.bin
	rm $*.ppc.o

%.ppc64.so: %.so.c
	powerpc64-linux-gnu-gcc $(GENERAL_CFLAGS) $*.so.c -shared -o $*.ppc64.so

%.ppc64.elf: %.elf.c
	powerpc64-linux-gnu-gcc $(GENERAL_CFLAGS) $*.elf.c -o $*.ppc64.elf

%.ppc64.elf: %.ppc64.elf.s
	powerpc64-linux-gnu-as $*.ppc64.elf.s -o $*.ppc64.elf.o
	powerpc64-linux-gnu-ld $*.ppc64.elf.o -o $*.ppc64.elf
	rm $*.ppc64.elf.o

%.ppc64.bin: %.ppc64.s
	powerpc64-linux-gnu-as $*.ppc64.s -o $*.ppc64.o
	powerpc64-linux-gnu-objcopy -O binary -j .text $*.ppc64.o $*.ppc64.bin
	rm $*.ppc64.o

%.riscv64.so: %.so.c
	riscv64-linux-gnu-gcc $(GENERAL_CFLAGS) $*.so.c -shared -o $*.riscv64.so

%.riscv64.elf: %.elf.c
	riscv64-linux-gnu-gcc $(GENERAL_CFLAGS) $*.elf.c -o $*.riscv64.elf

%.riscv64.elf: %.riscv64.elf.s
	riscv64-linux-gnu-as $*.riscv64.elf.s -o $*.riscv64.elf.o
	riscv64-linux-gnu-ld $*.riscv64.elf.o -o $*.riscv64.elf
	rm $*.riscv64.elf.o

%.riscv64.bin: %.riscv64.s
	riscv64-linux-gnu-as $*.riscv64.s -o $*.riscv64.o
	riscv64-linux-gnu-objcopy -O binary -j .text $*.riscv64.o $*.riscv64.bin
	rm $*.riscv64.o

%.xtensa.bin: %.xtensa.s
	xtensa-lx106-elf-as --no-transform --target-align --text-section-literals $*.xtensa.s -o $*.xtensa.o
	xtensa-lx106-elf-objcopy -O binary -j .text $*.xtensa.o $*.xtensa.bin
	rm $*.xtensa.o    

%.xtensa.elf: %.xtensa.elf.s
	xtensa-lx106-elf-as --no-transform --target-align --text-section-literals $*.xtensa.elf.s -o $*.xtensa.elf.o
	xtensa-lx106-elf-ld $*.xtensa.elf.o -o $*.xtensa.elf
	rm $*.xtensa.elf.o    

all: prereqs build

build: ${TARGETS}

clean:
	find . -name '*.bin' -type f -delete
	find . -name '*.elf' -type f -delete
	find . -name '*.o' -type f -delete
	find . -name '*.so' -type f -delete
	find . -name '*.pe' -type f -delete
	find . -name '*.dll' -type f -delete

nasm: $(NASM_TARGETS)

%.prereq:
	@which $*-gcc > /dev/null || (echo 'missing $*-gcc; on Ubuntu, install with `apt-get install gcc-$*`' || false)
	@which $*-as > /dev/null || (echo 'missing $*-as; on Ubuntu, install with `apt-get install binutils-$*`' || false)
	@which $*-objcopy > /dev/null || (echo 'missing $*-objcopy; on Ubuntu, install with `apt-get install binutils-$*`' || false)

prereqs: ${PREREQS}

check: ${TARGETS}
	for i in ${TARGETS}; do \
		echo $$i; \
		cstool x64 `xxd -p -c 0 $$i`; \
	done
