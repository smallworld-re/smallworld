from smallworld import cpus, state

class Smallworld:

    def __init__(self, cpu):
        self.cpu = cpu
        self.entry = None

        # here i want to do something s.t. all the registers and register aliases
        # are magically available in the sw=Smallworld object...
        for name, value in self.cpu.values.items():
            if type(value) == state.Register or type(value) == state.RegisterAlias:
                setattr(self, name, value)

    def map(self, start, code):
        pass

    def analyze(self):
        pass

    


class X86_64:

    def __init__(self):
        self.cpu = cpus.AMD64CPUState()

