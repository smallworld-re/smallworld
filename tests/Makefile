.PHONY: all build clean check
.DEFAULT_GOAL=all

SOURCES := $(wildcard */*.s)
BINS := $(patsubst %.s,%.bin,$(filter-out %.elf.s, $(SOURCES)))
ELFS := $(patsubst %.elf.s,%.elf,$(filter %.elf.s, $(SOURCES)))
MIPSEL_BINS := $(patsubst %.mips.bin,%.mipsel.bin,$(filter %.mips.bin,$(BINS)))
MIPS64EL_BINS := $(patsubst %.mips64.bin,%.mips64el.bin,$(filter %.mips64.bin,$(BINS)))
TARGETS := $(BINS) $(MIPSEL_BINS) $(MIPS64EL_BINS) $(ELFS)

NASM_SOURCES := $(wildcard *.amd64.s)
NASM_TARGETS := $(NASM_SOURCES:.s=.bin)

PREREQS := $(patsubst %,%.prereq,aarch64-linux-gnu arm-linux-gnueabi arm-linux-gnueabihf mips-linux-gnu mipsel-linux-gnu mips64-linux-gnuabi64 mips64el-linux-gnuabi64 powerpc-linux-gnu powerpc64-linux-gnu riscv64-linux-gnu sparc64-linux-gnu)

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

%.armel.bin: %.armel.s
	arm-linux-gnueabi-as $*.armel.s -o $*.armel.o
	arm-linux-gnueabi-objcopy -O binary -j .text $*.armel.o $*.armel.bin
	rm $*.armel.o

%.armhf.bin: %.armhf.s
	arm-linux-gnueabihf-as $*.armhf.s -o $*.armhf.o
	arm-linux-gnueabihf-objcopy -O binary -j .text $*.armhf.o $*.armhf.bin
	rm $*.armhf.o

%.i386.bin: %.i386.s
	i686-linux-gnu-as $*.i386.s -o $*.i386.o
	i686-linux-gnu-objcopy -O binary -j .text $*.i386.o $*.i386.bin
	rm $*.i386.o

%.mips.bin: %.mips.s
	mips-linux-gnu-as $*.mips.s -o $*.mips.o
	mips-linux-gnu-objcopy -O binary -j .text $*.mips.o $*.mips.bin
	rm $*.mips.o

%.mipsel.bin: %.mips.s
	mipsel-linux-gnu-as $*.mips.s -o $*.mipsel.o
	mipsel-linux-gnu-objcopy -O binary -j .text $*.mipsel.o $*.mipsel.bin
	rm $*.mipsel.o

%.mips64.bin: %.mips64.s
	mips64-linux-gnuabi64-as $*.mips64.s -o $*.mips64.o
	mips64-linux-gnuabi64-objcopy -O binary -j .text $*.mips64.o $*.mips64.bin
	rm $*.mips64.o

%.mips64el.bin: %.mips64.s
	mips64el-linux-gnuabi64-as $*.mips64.s -o $*.mips64el.o
	mips64el-linux-gnuabi64-objcopy -O binary -j .text $*.mips64el.o $*.mips64el.bin
	rm $*.mips64el.o

%.ppc.bin: %.ppc.s
	powerpc-linux-gnu-as $*.ppc.s -o $*.ppc.o
	powerpc-linux-gnu-objcopy -O binary -j .text $*.ppc.o $*.ppc.bin
	rm $*.ppc.o

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
