import abc
import builtins
import copy
import logging

import unicorn

from smallworld import analysis, cpus, executor, executors, initializer, state

logger = logging.getLogger(__name__)


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
                    f"Mapping new data f{r_new, label} overlaps existing f{r, l}"
                )
        # no overlap: add this data to the map
        self.memory[start] = (data, label)

    def map_region(self, region):
        self.map(region.start(), region.as_bytes(), region.label())

    def map_code(self, base=0x1000, entry=0x1000, code=None):
        assert not (code is None)
        self.map(base, code, "code")
        self.target = executor.Executable(image=code, entry=entry, base=base)

    def map_mem_into_cpu(self):
        # map all memory region into the cpu
        for addr, (data, label) in self.memory.items():
            logger.debug(
                f"writing smallworld memory region into cpu {label, addr, len(data)}"
            )
            mem_region = state.Memory(addr, len(data))
            mem_region.set(data)
            # hmm i think this will add this labeled mem region to cpu?
            setattr(self.cpu, label, mem_region)

    def analyze(self):
        self.map_mem_into_cpu()

        input_color_config = copy.deepcopy(self.config)
        input_color_exe = copy.deepcopy(self.target)
        input_color = analysis.InputColorizerAnalysis(input_color_config)
        input_color.run(input_color_exe)

    def emulate(self, num_instructions=10):
        emu = executors.UnicornExecutor(
            self.config.unicorn_arch, self.config.unicorn_mode
        )

        self.map_mem_into_cpu()
        # this should load regs and memory into executor from cpu
        self.cpu.apply(emu)
        # not thrilled with this
        emu.entrypoint = self.target.entry
        emu.exitpoint = self.target.entry + len(self.target.image)
        emu.write_register("pc", emu.entrypoint)
        for i in range(num_instructions):
            emu.step()
        # pull final state out of executor into cpu
        self.cpu.load(emu)
        return self.cpu


class X86_64:
    def __init__(self):
        self.cpu = cpus.AMD64CPUState()
        self.unicorn_arch = unicorn.UC_ARCH_X86
        self.unicorn_mode = unicorn.UC_MODE_64
        self.byteorder = "little"
        self.num_micro_executions = 5
        self.num_instructions = 10


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

    def to_bytes(self, value, size=None):
        if type(value) is builtins.bytes:
            return value
        elif type(value) is builtins.bytearray:
            return value
        elif type(value) is builtins.int:
            assert size, "need a size if pushing an int "
            return value.to_bytes(size, byteorder=self.config.byteorder)
        else:
            return bytes(value)


class Stack(Region):
    def __init__(self, base_addr, size, config):
        self.base_addr = base_addr
        self.size = size
        self.config = config
        self.memory = []
        self.used = 0

    def push(self, value, size=None):
        self.memory.append((value, size))
        self.used += len(self.to_bytes(value, size))
        assert self.used <= self.size

    def start(self) -> int:
        return self.base_addr

    def as_bytes(self) -> bytes:
        bytez = bytearray()
        for t in self.memory:
            bytez += self.to_bytes(t[0], t[1])
        return bytes(bytez)

    def label(self) -> str:
        return "stack"


class Heap(Region):
    @abc.abstractmethod
    def malloc(self, value, size=None) -> int:
        pass

    @abc.abstractmethod
    def free(self, addr) -> None:
        pass


class BumpAllocator(Heap):
    def __init__(self, base_addr, size, config):
        self.base_addr = base_addr
        self.size = size
        self.config = config
        self.memory = []
        self.used = 0

    def start(self) -> int:
        return self.base_addr

    def as_bytes(self) -> bytes:
        bytez = bytearray()
        for t in self.memory:
            bytez += self.to_bytes(t[0], t[1])
        return bytes(bytez)

    def label(self) -> str:
        return "bump allocator"

    def malloc(self, value, size=None) -> int:
        addr = self.base_addr + self.used
        self.memory.append((value, size))
        self.used += len(self.to_bytes(value, size))
        assert self.used <= self.size
        return addr

    def free(self, addr) -> None:
        raise NotImplementedError("Can't free")
