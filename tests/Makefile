.PHONY: all build clean check
.DEFAULT_GOAL=all

SOURCES := $(wildcard *.s)
MIPSEL_TARGETS := $(patsubst %.mips.s,%.mipsel.bin,$(wildcard *.mips.s)) 
MIPS64EL_TARGETS := $(patsubst %.mips64.s,%.mips64el.bin,$(wildcard *.mips64.s)) 
TARGETS := ${SOURCES:.s=.bin} $(MIPSEL_TARGETS) $(MIPS64EL_TARGETS)

CROSS_SOURCES := $(wildcard *.*.s)
NASM_SOURCES := $(filter-out $(CROSS_SOURCES),$(SOURCES))
NASM_TARGETS := $(NASM_SOURCES:.s=.bin)

PREREQS := $(patsubst %,%.prereq,aarch64-linux-gnu arm-linux-gnueabi arm-linux-gnueabihf mips-linux-gnu mipsel-linux-gnu mips64-linux-gnuabi64 mips64el-linux-gnuabi64 powerpc-linux-gnu powerpc64-linux-gnu riscv64-linux-gnu sparc64-linux-gnu)

%.aarch64.bin: %.aarch64.s
	aarch64-linux-gnu-as $*.aarch64.s -o $*.aarch64.o
	aarch64-linux-gnu-objcopy -O binary -j .text $*.aarch64.o $*.aarch64.bin
	rm $*.aarch64.o

%.armel.bin: %.armel.s
	arm-linux-gnueabi-as $*.armel.s -o $*.armel.o
	arm-linux-gnueabi-objcopy -O binary -j .text $*.armel.o $*.armel.bin
	rm $*.armel.o

%.armhf.bin: %.armhf.s
	arm-linux-gnueabihf-as $*.armhf.s -o $*.armhf.o
	arm-linux-gnueabihf-objcopy -O binary -j .text $*.armhf.o $*.armhf.bin
	rm $*.armhf.o

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

%.bin: %.s
	nasm $*.s -o $*.bin

all: prereqs build

build: ${TARGETS}

clean:
	rm -fr *.bin

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
