# NOTE: This requires setting ulimit core to actually produce core files.

CREATE_CORE=./create_core.sh

# Create core dumps only for platforms with test scripts.
#
# Not all platforms generate a guest core dump
# when run through qemu-user.
# (currently, the only offender is riscv64).

SCRIPTS=$(wildcard load/*.py)
CORES=$(patsubst load/%.py,%.elf.core,$(SCRIPTS))
REGS=$(patsubst load/%.py,%.elf.registers,$(SCRIPTS))

%.elf.core %.elf.registers : %.elf $(CREATE_CORE)
	$(CREATE_CORE) $<

.PHONY: all
all: $(CORES) $(REGS)

.PHONY : clean
clean: 
	rm -f *.core *.registers
