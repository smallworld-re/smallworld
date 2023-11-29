import abc
import angr
import claripy
import logging


class TypeDef(metaclass=abc.ABCMeta):
    """
    Base class for type definitions

    Defines a generic interface for type definition objects.
    """

    def __init__(self, name):
        self._name = name

    @abc.abstractmethod
    def __len__(self):
        """
        Get the length of this type in bytes
        """
        return

    @abc.abstractmethod
    def __eq__(self, other):
        return

    @abc.abstractmethod
    def to_bv(self, prefix="sw"):
        """
        Create a claripy expression representing an instance of this type
        """
        return

    @abc.abstractmethod
    def bind(self, env, bv):
        """
        Bind a claripy expression to this type
        """
        pass

    def _allocate(self, state, env=None):
        """
        Internal method for allocating this type on the heap.
        """
        addr = state.heap.allocate(len(self))
        self.log.debug(f"Allocating {self._name} of size {len(self)} at {addr:x}")
        data = self.to_bv()
        self.log.debug(f"Result: {data}")
        if env is not None:
            self.bind(env, data)
        state.memory.store(addr, data)

        return addr


class PrimitiveDef(TypeDef):
    """
    Typedef for primitive values

    These are irreducible byte fields,
    such as integers or pointers.
    """

    # TODO: Consider bit-scale types.
    # This could be useful for flag fields.
    def __init__(self, name, size, endian):
        super().__init__(name)
        self._size = size
        if endian == "LE":
            self._is_le = True
        elif endian == "BE":
            self._is_le = False
        else:
            raise ValueError(f'Unknown endianess {endian}; please specify "BE" or "LE"')

    def __len__(self):
        return self._size

    def __eq__(self, other):
        # Two PrimitiveDefs are equal if:
        #
        # - They are both PrimitiveDefs
        # - Their sizes are equal
        # - Their names are equal
        if not isinstance(other, PrimitiveDef):
            return False
        if self._name is None:
            if other._name is not None:
                return False
        else:
            if other._name is None:
                return False
            elif self._name != other._name:
                return False
        return self._size == other._size

    def __hash__(self):
        # TODO: Actually hash this.
        return id(self)

    def to_bv(self, prefix="sw"):
        if self._name is None:
            name = prefix
        else:
            name = prefix + "_" + self._name
        out = claripy.BVS(name, len(self) * 8)
        if self._is_le:
            return claripy.Reverse(out)
        else:
            return out

    def bind(self, env, bv):
        """
        Apply this type to a claripy AST.
        """
        if bv.op == "Reverse":
            # Unwrap any endian adjustments
            bv = bv.args[0]
        if bv.op != "BVS":
            raise ValueError(
                "Problem binding {bv} as {self._name}; primtives must be BVS"
            )
        env.bind_symbol(bv.args[0], self)

    def __str__(self):
        return f"<primitive {self._name} [{self._size}]>"


class PointerDef(PrimitiveDef):
    def __init__(self, size, endian, kind):
        super().__init__("pointer", size, endian)
        self._kind = kind

    def __eq__(self, other):
        # Two PointerDefs are equal if:
        #
        # - They are both PointerDefs
        # - Their enclosed types are equal
        if not isinstance(other, PointerDef):
            return False
        return self._kind == other._kind

    def __hash__(self):
        # The only thing discriminating pointers are their enclosed types
        return hash(self._kind)

    def allocate(self, state, env=None):
        return self._kind._allocate(state, env=env)

    def __str__(self):
        return f"<pointer {self._kind}>"


class StructDef(TypeDef):
    log = logging.getLogger("smallworld.struct")

    def __init__(self, name):
        super().__init__(name)
        self._fields = list()

    def add_field(self, name, kind: TypeDef):
        """
        Add a field to this struct definition
        """
        self._fields.append((name, kind))

    def __len__(self):
        out = 0
        for field_name, field_def in self._fields:
            out += len(field_def)
        return out

    def __eq__(self, other):
        # Two StructDefs are equivalent if:
        #
        # - They are both StructDefs
        # - They have the same name (struct types are unique by name)
        if not isinstance(other, StructDef):
            return False
        return self._name == other._name

    def __hash__(self):
        # Struct types are unique by name
        return hash(self._name)

    def bind(self, env, bv):
        if not bv.op == "Concat":
            raise ValueError(f"Problem binding {bv}; structs must be concats")
        for i in range(0, len(bv.args)):
            arg = bv.args[i]
            # Have the field tell us how to bind itself.
            self._fields[i][1].bind(env, arg)

    def to_bv(self, prefix="sw"):
        name = prefix + "_" + self._name
        fields = [f.to_bv(prefix=name + "_" + n) for n, f in self._fields]
        return claripy.Concat(*fields)

    def get_fields(self, state, addr):
        out = list()
        off = 0
        for field_name, field_def in self._fields:
            out.append(
                (
                    addr + off,
                    field_name,
                    claripy.Reverse(state.memory.load(addr + off, len(field_def))),
                )
            )
            off += len(field_def)
        return out

    def __str__(self):
        return f"<struct {self._name} [{len(self)}]>"


class TypeDefPlugin(angr.SimStatePlugin):
    """
    Angr state plugin for tracking typedefs

    This captures two concepts for a state:

    - Type bindings for addresses, registers and symbols
    - Instance addresses for symbols
    """

    log = logging.getLogger("smallworld.typedefs")

    def __init__(self):
        super().__init__()
        self._structdefs = dict()

        self._symbols = dict()
        self._sym_values = dict()
        self._registers = dict()
        self._addrs = dict()
        self._allocations = dict()

    @angr.SimStatePlugin.memo
    def copy(self, memo):
        dup = TypeDefPlugin()
        dup._structdefs.update(self._structdefs)
        dup._symbols.update(self._symbols)
        dup._sym_values.update(self._sym_values)
        dup._registers.update(self._registers)

        # heckin' multi-layer copy...
        for typedef, addrs in self._allocations.items():
            dup._allocations[typedef] = set(addrs)

        return dup

    def create_primitive(self, name, size):
        """
        Factory method for PrimitiveDef objects

        This auto-populates the 'endian' field
        based on the architecture of the current analysis.
        """
        endian = self.state.arch.memory_endness.name
        return PrimitiveDef(name, size, endian)

    def create_pointer(self, kind):
        """
        Factory method for PointerDef objects

        This auto-populates the 'endian' field
        based on the architecture of the current analysis,
        and the 'size' field based on the architecture's
        word size.
        """
        endian = self.state.arch.memory_endness.name
        size = self.state.arch.bits // 8
        return PointerDef(size, endian, kind)

    def create_struct(self, name):
        """
        Factory method for StructDef objects

        This automatically performs add_struct()
        on the new StructDef.
        """
        if name in self._structdefs:
            raise ValueError(f"Already have a struct def for {name}")
        out = StructDef(name)
        self.add_struct(out)
        return out

    def add_struct(self, structdef):
        """
        Add a struct type to this context for easy lookup
        """
        if structdef._name in self._structdefs:
            raise ValueError(f"Already have a struct def for {structdef._name}")
        self._structdefs[structdef._name] = structdef

    def get_struct(self, name):
        """
        Look up a struct type by its name
        """
        return self._structdefs[name]

    def bind_symbol(self, sym, typedef):
        """
        Bind a symbol to a typedef
        """
        if sym in self._symbols:
            raise ValueError(f"Already have a binding for {sym}")
        self._symbols[sym] = typedef

    def get_symbol_binding(self, sym):
        """
        Get the type binding for a symbol
        """
        if sym in self._symbols:
            return self._symbols[sym]
        return None

    def set_symbol(self, sym, val):
        """
        Set a concrete value for a symbol

        Symbols are static-single-assignment,
        so if they are collapsed to a concrete value,
        that assignment will stick.
        The assignment is normally bound up in the solver,
        making it annoying and expensive to recover.
        This feature lets us quickly recover our stuff
        """
        if sym in self._sym_values:
            raise ValueError(f"Already have value {self._sym_values[sym]} for {sym}")
        self._sym_values[sym] = val

    def get_symbol(self, sym):
        """
        Get a concrete value for a symbol
        """
        if sym in self._sym_values:
            return self._sym_values[sym]
        return None

    def bind_register(self, name, typedef):
        """
        Bind a register to a typedef

        Registers themselves don't have specific types.
        However, this only gets used in uninitialized value analysis;
        it only covers the type a register has before it's
        written by the program.
        """
        if name in self._registers:
            raise ValueError(f"Already have a binding for {name}")
        self._registers[name] = typedef

    def get_register_binding(self, name):
        """
        Get the type binding for a register

        Registers themselves don't have specific types.
        However, this only gets used in uninitialized value analysis;
        it only covers the type a register has before it's
        written by the program.
        """
        if name in self._registers:
            return self._registers[name]
        return None

    def bind_address(self, addr, typedef):
        if addr in self._addrs:
            raise ValueError(f"Already have a binding for {addr}")
        self._addrs[addr] = typedef

    def get_address_binding(self, addr):
        if addr in self._addrs:
            return self._addrs[addr]
        return None

    def allocate(self, typedef):
        addr = typedef.allocate(self.state, env=self)
        self._allocations.setdefault(typedef, set()).add(addr)
        return addr

    def get_allocs_for_type(self, typedef):
        if typedef in self._allocations:
            return list(self._allocations[typedef])
        return list()

    def pp(self, log, all_allocs=True):
        log("Register Bindings")
        for reg_name, reg_def in self._registers.items():
            log(f"\t{reg_name} -> {reg_def}")
        log("Symbol Bindings")
        for sym_name, sym_def in self._symbols.items():
            if sym_name in self._sym_values:
                log(f"\t{sym_name} -> {sym_def} ({self._sym_values[sym_name]:x})")
            else:
                log(f"\t{sym_name} -> {sym_def} (No Value)")
        if all_allocs:
            log("Allocations:")
            for typedef, addrs in self._allocations.items():
                log(f"- {typedef}")
                for addr in addrs:
                    log(f"\t- {addr:x}")
