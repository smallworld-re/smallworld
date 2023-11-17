.PHONY: all clean check

SOURCES := $(wildcard *.s)
TARGETS := ${SOURCES:.s=.bin}

%.bin: %.s
	nasm $*.s -o $*.bin

all: ${TARGETS}

clean:
	rm -fr *.bin

check: ${TARGETS}
	for i in ${TARGETS}; do \
		echo $$i; \
		cstool x64 `xxd -p -c 0 $$i`; \
	done
