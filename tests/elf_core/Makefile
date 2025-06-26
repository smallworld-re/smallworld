CREATE_CORE=./create_core.sh
ELFS=$(wildcard *.elf)
CORES=$(patsubst %,%.core,$(ELFS))
REGS=$(patsubst %,%.registers,$(ELFS))

%.elf.core %.registers : %.elf $(CREATE_CORE)
	$(CREATE_CORE) $<

.PHONY: all
all: $(CORES) $(REGS)

.PHONY : clean
clean: 
	rm -f *.core *.registers
