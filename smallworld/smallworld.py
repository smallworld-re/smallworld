from smallworld import cpus, state, executable, initializer

def overlap(r1, r2):
    if (r1.start >= r2.stop) or (r2.start >= r1.stop):
        # they do not overlap
        return False
    return True


class Smallworld:

    def __init__(self, cpu):
        self.cpu = cpu
        self.memory = {}
        zero = initializer.ZeroInitializer()
        self.cpu.initialize(zero)
        

    def map(self, start, data, label):
        """
        Map this data at this address
        """
        # make sure mapping this data at this addr won't overlap any existing mappings
        for a, dl in self.memory.items():
            (d,l) = dl
            r = range(a, a + len(d))
            r_new = range(start, start + len(data))
            if overlap(r, r_new):
                raise ValueError(f"Mapping new data f{r_new,label} overlaps existing f{r,l}")
        # no overlap: add this data to the map
        self.memory[start] = (data, label)

    def map_code(self, base=0x1000, entry=0x1000, code=None):
        assert not (code is None)
        self.map(base, code, "code")
        self.target = executable.Executable(image=code, entry=entry, base=base)

    def analyze(self):
        print("analyze: not yet implemented")

    def emulate(self, num_instructions=10, executor=None):
        if executor is None:
            # you must have already told me what the executor is
            # and set it up?  let's check
            assert not (self.executor is None)
        else:
            # set or change of executor I guess?
            self.executor = executor        
            
        # map all memory region into the cpu
        for (addr, (data, label)) in self.memory.items():
            print(f"emulate: writing memory region into cpu {label,addr,len(data)}") 
            mem_region = state.Memory(addr, len(data))
            mem_region.set(data)
            # hmm i think this will add this labeled mem region to cpu?
            setattr(self.cpu, label, mem_region)
        # this should load regs and memory into executor from cpu
        self.cpu.apply(self.executor)
        # not thrilled with this
        self.executor.entrypoint = self.target.entry
        self.executor.exitpoint = self.target.entry + len(self.target.image)        
        self.executor.write_register("pc", self.executor.entrypoint)
        for i in range(num_instructions):
            self.executor.step()
        # pull final state out of executor into cpu
        self.cpu.load(self.executor)
        return self.cpu

        
        
        
    


class X86_64:

    def __init__(self):
        self.cpu = cpus.AMD64CPUState()

