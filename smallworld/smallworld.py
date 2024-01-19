from smallworld import cpus, state, executable

def overlap(r1, r2):
    if (r1.start >= r2.stop) or (r2.start >= r1.stop):
        # they do not overlap
        return False
    return True


class Smallworld:

    def __init__(self, cpu):
        self.cpu = cpu
        self.memory = {}

        # here i want to do something s.t. all the registers and register aliases
        # are magically available in the sw=Smallworld object...
        for name, value in self.cpu.values.items():
            if type(value) == state.Register or type(value) == state.RegisterAlias:
                setattr(self, name, value)

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
        self.memory[start] = data

    def map_code(self, base=0x1000, entry=0x1000, code=None):
        assert not (code is None)
        self.map(base, code, "code")
        self.target = executable.Executable(image=code, entry=entry, base=base)

    def analyze(self):
        print("analyze: not yet implemented")

    def emulate(self, num_instructions=10, executor=None):
        import pdb
        pdb.set_trace()
        if executor is None:
            # you must have already told me what the executor is
            # and set it up?  let's check
            assert not (self.executor is None)
        else:
            # set or change of executor I guess?
            self.executor = executor
        # for each emulation, we need to map into the executor all memory elements
        for (addr, (data, label)) in self.memory.items():
            print(f"emulate: writing data into executor {label,addr,len(data)}") 
            self.executor.write_memory(addr, data)
        for i in range(num_instructions):
            self.executor.step()
        # pull final state out of executor into cpu
        self.cpu.load(self.executor)
        return self.cpu

        
        
        
    


class X86_64:

    def __init__(self):
        self.cpu = cpus.AMD64CPUState()

