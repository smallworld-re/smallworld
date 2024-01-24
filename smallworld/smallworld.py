import base64
import logging
import random
import abc
import builtins

import unicorn

from smallworld import cpus, executable, executors, initializer, state, hinting, utils


logger = logging.getLogger(__name__)

hinter = hinting.getHinter(__name__)
utils.setup_hinting(verbose=True, stream=True, file="hints.jsonl")

regular_regs_64 = ["rax", "rbx", "rcx", "rdx", 
                   "rdi", "rsi", "rbp", "rsp",
                   "r8", "r9", "r10" , "r11" , "r12" , "r13" , "r14" , "r15"]

regular_regs_32 = ["eax", "ebx", "ecx", "edx", 
                   "edi", "esi", "ebp", "esp"]

def overlap(r1, r2):
    if (r1.start >= r2.stop) or (r2.start >= r1.stop):
        # they do not overlap
        return False
    return True


class Smallworld:
    def __init__(self, config):
        self.config = config
        self.cpu = config.cpu
        self.memory = {}
        zero = initializer.ZeroInitializer()
        self.cpu.initialize(zero)

    def map(self, start, data, label):
        """
        Map this data at this address
        """
        # make sure mapping this data at this addr won't overlap any existing mappings
        for a, dl in self.memory.items():
            (d, l) = dl
            r = range(a, a + len(d))
            r_new = range(start, start + len(data))
            if overlap(r, r_new):
                raise ValueError(
                    f"Mapping new data f{r_new,label} overlaps existing f{r,l}"
                )
        # no overlap: add this data to the map
        self.memory[start] = (data, label)

    def map_region(self, region):
        self.map(region.start(), region.as_bytes(), region.label())

    def map_code(self, base=0x1000, entry=0x1000, code=None):
        assert not (code is None)
        self.map(base, code, "code")
        self.target = executable.Executable(image=code, entry=entry, base=base)

    def map_mem_into_cpu(self):
        # map all memory region into the cpu
        for addr, (data, label) in self.memory.items():
            logger.debug(f"writing smallworld memory region into cpu {label,addr,len(data)}")
            mem_region = state.Memory(addr, len(data))
            mem_region.set(data)
            # hmm i think this will add this labeled mem region to cpu?
            setattr(self.cpu, label, mem_region)

    def registers(self):
        """
        Generator to iterate over registers in the cpu
        """
        for name,stv in self.cpu.values.items():
            if type(stv) == state.Register:
                yield (name, stv)

    def colorize_registers(self, regular=True):
        # colorize registers 
        for name,reg in self.registers():
            if (regular and (name in regular_regs_64)) or (not regular):
                # only colorize "regular" registers of full 64 bits
                reg.set(random.randint(0, 0xfffffffffffffff))
        # but now go through all 64 and 32-bit reg aliases and record intial values
        r0 = {}
        for name,stv in self.cpu.values.items():
            if type(stv) == state.Register or type(stv) == state.RegisterAlias:
                if (regular and (name in regular_regs_64 or name in regular_regs_32)) or (not regular):
                    r0[stv.get()] = name
                    logger.debug(f"color[{name}] = {stv.get():x}")
        return r0

    def check_register_colors(self, r0, reg_subset, regular=True):
        # return set of regs in reg_subset whose current value 
        # is in colorized map r0
        # [relies on reg values being in self.cpu]
        r_c = []
        for name,stv in self.cpu.values.items():
            if not (type(stv) == state.Register or type(stv) == state.RegisterAlias):
                continue
            if not (name in reg_subset):
                continue
            value = stv.get()
            logger.debug(f"check_register_colors: {name} = {value:x}")
            if (name in reg_subset) and value in r0:
                logger.debug("-- that's a color")
                # name is a register in the subset 
                # *and* in the colorizer map
                # and this is name of input register it corresponds to
                input_name = r0[value]
                p = (name, input_name)
                r_c.append(p)
        return r_c

    def instruction_uses(self, instruction):
        # determine set of registers this instruction uses
        (regs_read, regs_written) = instruction.regs_access()
        r_read = []
        for r in regs_read:
            name = instruction.reg_name(r)
            r_read.append(name)
        return r_read

    def check_instruction_regs_colors(self, r0, instruction):
        # r0 is register colors: map from initial random value at start of micro exec
        # to corresponding initial reg name
        # registers used (or read) by this instruction
        # returns a list of pairs (rn, irn)
        # where rn is the name of a register used by instruction
        # and irn is the original register name it appears to correspond to
        # based on colorizing
        registers_used = self.instruction_uses(instruction)
        logger.debug(f"registers_used = {registers_used}")
        # This should be the set of registers used by this 
        # instruction correspond to colorized (i.e. unitialized) values
        return self.check_register_colors(r0, registers_used)

    def analyze(self, num_micro_executions=5, num_instructions=10):
        """A very simple analysis using colorizing and unicorn.  We run
        multiple micro-executions of the code starting from same
        entry.  At the start of each, we randomize register values but
        also create a map from those specific values to name of
        register initialized that way.  We then single step emulation
        and *before* each instruction we check to see if any of the
        registers *used* by this instruction have colorized values,
        indicating they are likely direct copies of input registers.
        Any such uses of input registers are hinted
        """
        for i in range(num_micro_executions):
            # NB: perform more than one micro-exec
            # since paths could diverge given random intial
            # reg values
            executor = executors.UnicornExecutor(
                self.config.unicorn_arch, self.config.unicorn_mode
            )            
            logger.info("-------------------------")
            logger.info(f"micro exec #{i}")
            # colorize regs before beginning this micro exec
            r0 = self.colorize_registers()
            for (value, name) in r0.items():
                logger.debug(f"{name} = {value:x}")
            self.map_mem_into_cpu()
            self.cpu.apply(executor)
            executor.entrypoint = self.target.entry
            executor.exitpoint = self.target.entry + len(self.target.image)
            executor.write_register("pc", executor.entrypoint)
            for j in range(num_instructions):
                pc = executor.read_register("pc")
                code = executor.read_memory(pc, 15)  # longest possible instruction
                if code is None:
                    assert False, "impossible state"
                (instructions, disas) = executor.disassemble(code, 1)                
                instruction = instructions[0]
                # pull state back out of the executor for inspection
                self.cpu.load(executor)
                # determine if, for this instruction (before execution)
                # any of the regs that will be read have values in colorized map
                # meaning they are uninitialized values
                rc = self.check_instruction_regs_colors(r0, instruction)           
                for (reg_name, input_reg_name) in rc:
                    hint = hinting.InputUseHint(
                        message="Register used in instruction has same value as Input register", 
                        input_register = input_reg_name,
#                        instruction = instruction,
                        instruction = base64.b64encode(instruction.bytes).decode(),
                        pc = pc,
                        micro_exec_num = i,
                        instruction_num = j,
                        use_register = reg_name
                    )
                    hinter.info(hint)
                try:
                    done = executor.step()                
                    if done:
                        break
                except Exception as e:
                    hint = hinting.EmulationException(
                        message="Emulation single step raised an exception",
                        instruction = base64.b64encode(instruction.bytes).decode(),
                        pc = pc,
                        micro_exec_num = i,
                        instruction_num = j,
                        exception = str(e)
                    )
                    hinter.info(hint)
                    logger.info(e)
                    break
            
                
    def emulate(self, num_instructions=10, executor=None):
        executor = executors.UnicornExecutor(
            self.config.unicorn_arch, self.config.unicorn_mode
        )

        self.map_mem_into_cpu()
        # this should load regs and memory into executor from cpu
        self.cpu.apply(executor)
        # not thrilled with this
        executor.entrypoint = self.target.entry
        executor.exitpoint = self.target.entry + len(self.target.image)
        executor.write_register("pc", executor.entrypoint)
        for i in range(num_instructions):
            executor.step()
        # pull final state out of executor into cpu
        self.cpu.load(executor)
        return self.cpu


class X86_64:
    def __init__(self):
        self.cpu = cpus.AMD64CPUState()
        self.unicorn_arch = unicorn.UC_ARCH_X86
        self.unicorn_mode = unicorn.UC_MODE_64
        self.byteorder = "little"


class Region:
    @abc.abstractmethod
    def start(self) -> int:
        pass

    @abc.abstractmethod
    def as_bytes(self) -> bytes:
        pass

    @abc.abstractmethod
    def label(self) -> str:
        pass


class Stack(Region):
    def __init__(self, base_addr, size, config):
        self.base_addr = base_addr
        self.size = size
        self.config = config
        self.memory = bytearray()

    def push(self, value, size=None):
        match type(value):
            case builtins.bytes:
                self.memory += value
            case builtins.bytearray:
                self.memory += value
            case builtins.int:
                assert size, "need a size if pushing an int"
                self.memory += value.to_bytes(size, byteorder=self.config.byteorder)
        assert len(self.memory) <= self.size

    def start(self) -> int:
        return self.base_addr

    def as_bytes(self) -> bytes:
        return bytes(self.memory)

    def label(self) -> str:
        return "stack"
