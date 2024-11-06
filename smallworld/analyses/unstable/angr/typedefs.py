import ctypes
import logging

import angr
import claripy

log = logging.getLogger(__name__)


class TypeDefPlugin(angr.SimStatePlugin):
    """Angr state plugin for tracking typedefs

    This captures two concepts for a state:

    - Type bindings for addresses, registers and symbols
    - Instance addresses for symbols
    """

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

    def ctype_to_bv(self, typedef, prefix="sw"):
        if hasattr(typedef, "_fields_"):
            off = 0
            fielddefs = list()
            for name, fielddef in typedef._fields_:
                field_off = getattr(typedef, name).offset
                if field_off > off:
                    # handle padding
                    fielddefs.append(claripy.BVS("padding", (field_off - off) * 8))
                    off = field_off
                fielddefs.append(self.ctype_to_bv(fielddef, f"{prefix}_{name}"))
                off += ctypes.sizeof(fielddef)

            return claripy.Concat(*fielddefs)
        else:
            res = claripy.BVS(prefix, ctypes.sizeof(typedef) * 8)
            self.bind_symbol(res, typedef)
            res = claripy.Reverse(res)
            return res

    def add_struct(self, structdef):
        """Add a struct type to this context for easy lookup"""
        if structdef._name in self._structdefs:
            raise ValueError(f"Already have a struct def for {structdef._name}")
        self._structdefs[structdef._name] = structdef

    def get_struct(self, name):
        """Look up a struct type by its name"""
        return self._structdefs[name]

    def bind_symbol(self, sym, typedef):
        """Bind a symbol to a typedef"""
        if sym in self._symbols:
            raise ValueError(f"Already have a binding for {sym}")
        self._symbols[sym.args[0]] = typedef

    def get_symbol_binding(self, sym):
        """Get the type binding for a symbol"""
        if sym in self._symbols:
            return self._symbols[sym]
        return None

    def set_symbol(self, sym, val):
        """Set a concrete value for a symbol

        Symbols are static-single-assignment,
        so if they are collapsed to a concrete value,
        that assignment will stick.
        The assignment is normally bound up in the solver,
        making it annoying and expensive to recover.
        This feature lets us quickly recover our stuff
        """
        log.info(f"Setting {sym} to {val}")
        if sym in self._sym_values:
            raise ValueError(f"Already have value {self._sym_values[sym]} for {sym}")
        self._sym_values[sym] = val

    def get_symbol(self, sym):
        """Get a concrete value for a symbol"""
        if sym in self._sym_values:
            return self._sym_values[sym]
        return None

    def bind_register(self, name, typedef):
        """Bind a register to a typedef

        Registers themselves don't have specific types.
        However, this only gets used in uninitialized value analysis;
        it only covers the type a register has before it's
        written by the program.
        """
        if name in self._registers:
            raise ValueError(f"Already have a binding for {name}")
        self._registers[name] = typedef

    def get_register_binding(self, name):
        """Get the type binding for a register

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
        addr = self.state.heap.allocate(ctypes.sizeof(typedef))

        rep = self.ctype_to_bv(typedef)

        self._allocations.setdefault(typedef, set()).add(addr)
        log.debug(f"Storing {rep} at {addr:x}")
        self.state.memory.store(addr, rep)
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
