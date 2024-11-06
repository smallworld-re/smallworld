.PHONY: all build clean check
.DEFAULT_GOAL=all

SOURCES := $(wildcard */*.s)
BINS := $(patsubst %.s,%.bin,$(filter-out %.elf.s, $(SOURCES)))
ELFS := $(patsubst %.elf.s,%.elf,$(filter %.elf.s, $(SOURCES)))
MIPSEL_BINS := $(patsubst %.mips.bin,%.mipsel.bin,$(filter %.mips.bin,$(BINS)))
MIPSEL_ELFS := $(patsubst %.mips.elf,%.mipsel.elf,$(filter %.mips.elf,$(ELFS)))
MIPS64EL_BINS := $(patsubst %.mips64.bin,%.mips64el.bin,$(filter %.mips64.bin,$(BINS)))
MIPS64EL_ELFS := $(patsubst %.mips64.elf,%.mips64el.elf,$(filter %.mips64.elf,$(ELFS)))
TARGETS := $(BINS) $(MIPSEL_BINS) $(MIPS64EL_BINS) $(ELFS) $(MIPSEL_ELFS) $(MIPS64EL_ELFS)

NASM_SOURCES := $(wildcard *.amd64.s)
NASM_TARGETS := $(NASM_SOURCES:.s=.bin)

PREREQS := $(patsubst %,%.prereq,aarch64-linux-gnu arm-linux-gnueabi arm-linux-gnueabihf mips-linux-gnu mipsel-linux-gnu mips64-linux-gnuabi64 mips64el-linux-gnuabi64 powerpc-linux-gnu powerpc64-linux-gnu riscv64-linux-gnu sparc64-linux-gnu)

%.aarch64.elf: %.aarch64.elf.s
	aarch64-linux-gnu-as $*.aarch64.elf.s -o $*.aarch64.elf.o
	aarch64-linux-gnu-ld $*.aarch64.elf.o -o $*.aarch64.elf
	rm $*.aarch64.elf.o

%.aarch64.bin: %.aarch64.s
	aarch64-linux-gnu-as $*.aarch64.s -o $*.aarch64.o
	aarch64-linux-gnu-objcopy -O binary -j .text $*.aarch64.o $*.aarch64.bin
	rm $*.aarch64.o

%.amd64.elf: %.amd64.elf.s
	as $*.amd64.elf.s -o $*.amd64.elf.o
	ld $*.amd64.elf.o -o $*.amd64.elf
	rm $*.amd64.elf.o

%.amd64.bin: %.amd64.s
	nasm $*.amd64.s -o $*.amd64.bin

%.armel.elf: %.armel.elf.s
	arm-linux-gnueabi-as $*.armel.elf.s -o $*.armel.elf.o
	arm-linux-gnueabi-ld $*.armel.elf.o -o $*.armel.elf
	rm $*.armel.elf.o

%.armel.bin: %.armel.s
	arm-linux-gnueabi-as $*.armel.s -o $*.armel.o
	arm-linux-gnueabi-objcopy -O binary -j .text $*.armel.o $*.armel.bin
	rm $*.armel.o

%.armhf.elf: %.armhf.elf.s
	arm-linux-gnueabihf-as $*.armhf.elf.s -o $*.armhf.elf.o
	arm-linux-gnueabihf-ld $*.armhf.elf.o -o $*.armhf.elf
	rm $*.armhf.elf.o

%.armhf.bin: %.armhf.s
	arm-linux-gnueabihf-as $*.armhf.s -o $*.armhf.o
	arm-linux-gnueabihf-objcopy -O binary -j .text $*.armhf.o $*.armhf.bin
	rm $*.armhf.o

%.i386.elf: %.i386.elf.s
	i686-linux-gnu-as $*.i386.elf.s -o $*.i386.elf.o
	i686-linux-gnu-ld $*.i386.elf.o -o $*.i386.elf
	rm $*.i386.elf.o

%.i386.bin: %.i386.s
	i686-linux-gnu-as $*.i386.s -o $*.i386.o
	i686-linux-gnu-objcopy -O binary -j .text $*.i386.o $*.i386.bin
	rm $*.i386.o

%.mips.elf: %.mips.elf.s
	mips-linux-gnu-as $*.mips.elf.s -o $*.mips.elf.o
	mips-linux-gnu-ld $*.mips.elf.o -o $*.mips.elf
	rm $*.mips.elf.o

%.mips.bin: %.mips.s
	mips-linux-gnu-as $*.mips.s -o $*.mips.o
	mips-linux-gnu-objcopy -O binary -j .text $*.mips.o $*.mips.bin
	rm $*.mips.o

%.mipsel.elf: %.mips.elf.s
	mipsel-linux-gnu-as $*.mips.elf.s -o $*.mipsel.elf.o
	mipsel-linux-gnu-ld $*.mipsel.elf.o -o $*.mipsel.elf
	rm $*.mipsel.elf.o

%.mipsel.bin: %.mips.s
	mipsel-linux-gnu-as $*.mips.s -o $*.mipsel.o
	mipsel-linux-gnu-objcopy -O binary -j .text $*.mipsel.o $*.mipsel.bin
	rm $*.mipsel.o

%.mips64.elf: %.mips64.elf.s
	mips64-linux-gnuabi64-as $*.mips64.elf.s -o $*.mips64.elf.o
	mips64-linux-gnuabi64-ld $*.mips64.elf.o -o $*.mips64.elf
	rm $*.mips64.elf.o

%.mips64.bin: %.mips64.s
	mips64-linux-gnuabi64-as $*.mips64.s -o $*.mips64.o
	mips64-linux-gnuabi64-objcopy -O binary -j .text $*.mips64.o $*.mips64.bin
	rm $*.mips64.o

%.mips64el.elf: %.mips64.elf.s
	mips64el-linux-gnuabi64-as $*.mips64.elf.s -o $*.mips64el.elf.o
	mips64el-linux-gnuabi64-ld $*.mips64el.elf.o -o $*.mips64el.elf
	rm $*.mips64el.elf.o

%.mips64el.bin: %.mips64.s
	mips64el-linux-gnuabi64-as $*.mips64.s -o $*.mips64el.o
	mips64el-linux-gnuabi64-objcopy -O binary -j .text $*.mips64el.o $*.mips64el.bin
	rm $*.mips64el.o

%.ppc.elf: %.ppc.elf.s
	powerpc-linux-gnu-as $*.ppc.elf.s -o $*.ppc.elf.o
	powerpc-linux-gnu-ld $*.ppc.elf.o -o $*.ppc.elf
	rm $*.ppc.elf.o

%.ppc.bin: %.ppc.s
	powerpc-linux-gnu-as $*.ppc.s -o $*.ppc.o
	powerpc-linux-gnu-objcopy -O binary -j .text $*.ppc.o $*.ppc.bin
	rm $*.ppc.o

%.ppc64.elf: %.ppc64.elf.s
	powerpc64-linux-gnu-as $*.ppc64.elf.s -o $*.ppc64.elf.o
	powerpc64-linux-gnu-ld $*.ppc64.elf.o -o $*.ppc64.elf
	rm $*.ppc64.elf.o

%.ppc64.bin: %.ppc64.s
	powerpc64-linux-gnu-as $*.ppc64.s -o $*.ppc64.o
	powerpc64-linux-gnu-objcopy -O binary -j .text $*.ppc64.o $*.ppc64.bin
	rm $*.ppc64.o

%.riscv64.bin: %.riscv64.s
	riscv64-linux-gnu-as $*.riscv64.s -o $*.riscv64.o
	riscv64-linux-gnu-objcopy -O binary -j .text $*.riscv64.o $*.riscv64.bin
	rm $*.riscv64.o

%.sparc64.bin: %.sparc64.s
	sparc64-linux-gnu-as $*.sparc64.s -o $*.sparc64.o
	sparc64-linux-gnu-objcopy -O binary -j .text $*.sparc64.o $*.sparc64.bin
	rm $*.sparc64.o

all: prereqs build

build: ${TARGETS}

clean:
	find . -name '*.bin' -type f -delete
	find . -name '*.elf' -type f -delete
	find . -name '*.o' -type f -delete

nasm: $(NASM_TARGETS)

%.prereq:
	@which $*-as > /dev/null || (echo 'missing $*-as; on Ubuntu, install with `apt-get install binutils-$*`' || false)
	@which $*-objcopy > /dev/null || (echo 'missing $*-objcopy; on Ubuntu, install with `apt-get install binutils-$*`' || false)

prereqs: ${PREREQS}

check: ${TARGETS}
	for i in ${TARGETS}; do \
		echo $$i; \
		cstool x64 `xxd -p -c 0 $$i`; \
	done
