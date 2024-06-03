import logging

import claripy
from angr.storage import MemoryMixin

from ... import hinting, instructions
from .base import BaseMemoryMixin
from .terminate import PathTerminationSignal
from .typedefs import PointerDef
from .visitor import EvalVisitor

log = logging.getLogger(__name__)
hinter = hinting.getHinter(__name__)
visitor = EvalVisitor()


class ModelMemoryMixin(BaseMemoryMixin):
    """
    Mixin for detecting model violations in memory ops.
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._setup_tui()

    @MemoryMixin.memo
    def copy(self, memo):
        o = super().copy(memo)
        o._setup_tui()
        return o

    def _handle_typed_value(self, typedef, default, pretty):
        """
        Process user decision for a typed variable without a value

        Pointer types allow the following options:

        - Allocate a new region on the heap, and point to it.
        - Ase a reference to a new heap region

        All types allow the following options:

        - Use a placeholder symbol to track this value
        - Use a user-provided integer as a concrete value (not recommended for multi-KB structs)
        - Use zero/NULL as a concrete value
        - Use whatever default angr suggests
        - Print details of the current situation
        - Abort this execution path
        - Abort all execution
        """

        options = {
            "placeholder": self.typed_value_placeholder,
            "const": self.typed_value_const,
            "null": self.typed_value_null,
            "ignore": self.typed_value_ignore,
            "stop": self.typed_value_stop,
            "quit": self.typed_value_quit,
        }

        if isinstance(typedef, PointerDef):
            option = "alloc"
            options.update(
                {
                    "alloc": self.typed_value_alloc,
                    "reuse": self.typed_value_reuse,
                }
            )
        else:
            option = "placeholder"
        return options[option](typedef=typedef, default=default, pretty=pretty)

    def _handle_untyped_register(self, reg_name, default):
        options = {
            "ignore": self.untyped_value_ignore,
            "bind": self.untyped_addr_bind,
            "stop": self.untyped_value_stop,
            "quit": self.untyped_value_quit,
        }
        option = "ignore"
        return options[option](reg_name=reg_name, default=default)

    def _handle_untyped_address(self, addr, default):
        options = {
            "ignore": self.untyped_value_ignore,
            "bind": self.untyped_addr_bind,
            "stop": self.untyped_value_stop,
            "quit": self.untyped_value_quit,
        }
        option = "ignore"
        return options[option](addr=addr, default=default)

    def _handle_untyped_symbol(self, sym_name, default):
        options = {
            "ignore": self.untyped_value_ignore,
            "bind": self.untyped_sym_bind,
            "stop": self.untyped_value_stop,
            "quit": self.untyped_value_quit,
        }
        option = "ignore"
        return options[option](sym_name=sym_name, default=default)

    def _default_value(self, addr, size, **kwargs):
        environ = self.state.typedefs
        res = super()._default_value(addr, size, **kwargs)
        (cinsn,) = list(
            filter(
                lambda x: x.address == self.state._ip.concrete_value,
                self.state.block().capstone.insns,
            )
        )
        if self.id == "reg":
            reg_name = self.state.arch.register_size_names[(addr, size)]
            reg_def = environ.get_register_binding(reg_name)
            if reg_def is not None:
                res = self._handle_typed_value(reg_def, res, reg_name)
                hint = hinting.TypedUnderSpecifiedRegisterHint(
                    message="Register has type, but no value",
                    typedef=str(reg_def),
                    pc=self.state._ip.concrete_value,
                    register=reg_name,
                    instruction=instructions.Instruction.from_capstone(cinsn),
                    value=str(res),
                )
                hinter.info(hint)
            else:
                res = self._handle_untyped_register(reg_name, res)
                hint = hinting.UntypedUnderSpecifiedRegisterHint(
                    message="Register has no type or value",
                    pc=self.state._ip.concrete_value,
                    register=reg_name,
                    instruction=instructions.Instruction.from_capstone(cinsn),
                    value=str(res),
                )
                hinter.info(hint)
            if isinstance(res, int):
                res = self.state.solver.BVV(res, size * 8)
        else:
            addr_def = environ.get_address_binding(addr)
            if addr_def is not None:
                res = self._handle_typed_value(addr_def, res, addr)
                hint = hinting.TypedUnderSpecifiedMemoryHint(
                    message="Memory has type, but no value",
                    typedef=str(addr_def),
                    pc=self.state._ip.concrete_value,
                    address=addr,
                    size=size,
                    instruction=instructions.Instruction.from_capstone(cinsn),
                    value=str(res),
                )
                hinter.info(hint)
            else:
                hint = hinting.UntypedUnderSpecifiedMemoryHint(
                    message="Memory has no type or value",
                    pc=self.state._ip.concrete_value,
                    address=addr,
                    size=size,
                    instruction=instructions.Instruction.from_capstone(cinsn),
                    value=str(res),
                )
                hinter.info(hint)
                self._handle_untyped_address(addr, res)

        return res

    def _concretize_bindings(self, supercall, addr, strategies, condition):
        """
        Concretization strategy for interrogating model

        This is the same code for both reads and writes.
        """
        environ = self.state.typedefs
        (cinsn,) = list(
            filter(
                lambda x: x.address == self.state._ip.concrete_value,
                self.state.block().capstone.insns,
            )
        )

        log.debug(f"\tAddr:       {addr}")
        bindings = dict()
        complete = True
        for v in filter(lambda x: x.op == "BVS", addr.leaf_asts()):
            value = environ.get_symbol(v.args[0])
            if value is None:
                binding = environ.get_symbol_binding(v.args[0])
                if binding is None:
                    log.warn(
                        f"Symbol {v} (part of address expression {addr}) has no type"
                    )
                    value = self._handle_untyped_symbol(v, None)
                    if value is None:
                        complete = False
                        continue
                    hint = hinting.TypedUnderSpecifiedAddressHint(
                        message="Symbol has no type",
                        pc=self.state._ip.concrete_value,
                        symbol=v.args[0],
                        addr=str(addr),
                        instruction=instructions.Instruction.from_capstone(cinsn),
                        value=str(value),
                    )
                else:
                    log.warn(
                        f"Symbol {v} (part of address expression {addr}) has type {binding}, but no value"
                    )
                    while True:
                        value = self._handle_typed_value(binding, None, addr)
                        if value is not None and not self.state.solver.satisfiable(
                            extra_constraints=[v == value]
                        ):
                            log.warn(f"Selection {value:x} is not valid")
                            self._untyped_value_stop()
                        break
                    if value is None:
                        complete = False
                        continue
                    hint = hinting.TypedUnderSpecifiedAddressHint(
                        message="Symbol has type, but no value",
                        typedef=str(binding),
                        pc=self.state._ip.concrete_value,
                        symbol=v.args[0],
                        addr=str(addr),
                        instruction=instructions.Instruction.from_capstone(cinsn),
                        value=str(value),
                    )
                    hinter.info(hint)
                environ.set_symbol(v.args[0], value)
                if isinstance(value, int):
                    pretty_value = hex(value)
                else:
                    log.error(f"Bad value for {v.args[0]}: {value} ({type(value)})")
                    quit(1)
                log.debug(f"\tNew Value for {v.args[0]}: {pretty_value}")
            else:
                log.debug(f"\tExisting Value for {v.args[0]}: {value:x}")
            bindings[v.args[0]] = claripy.BVV(value, 64)
        if complete:
            value = visitor.visit(addr, bindings=bindings)
            if not isinstance(value, int):
                value = value.concrete_value
            res = [value]
        else:
            res = supercall(addr, strategies=strategies, condition=condition)
        log.debug("\tResults:")
        for v in res:
            if isinstance(v, int):
                log.debug(f"\t\t{v:x}")
            else:
                log.debug(f"\t\t{v}")
        return res

    def concretize_read_addr(self, addr, strategies=None, condition=None):
        log.debug("Concretizing on read:")
        return self._concretize_bindings(
            super().concretize_read_addr, addr, strategies, condition
        )

    def concretize_write_addr(self, addr, strategies=None, condition=None):
        log.debug("Concretizing on write:")
        return self._concretize_bindings(
            super().concretize_write_addr, addr, strategies, condition
        )

    # TUI handler functions.  Fear the boilerplate.

    def typed_value_alloc(self, typedef=None, **kwargs):
        # User wants to allocate a new instance
        environ = self.state.typedefs
        res = environ.allocate(typedef)
        log.warn(f"Allocated {len(typedef._kind)} bytes at {res:x}")
        return res

    def typed_value_reuse(self, typedef=None, **kwargs):
        raise NotImplementedError("Reuse requires human input.")

    def typed_value_placeholder(self, typedef=None, **kwargs):
        # User wants to assign a placeholder symbol, not a real value.
        res = typedef.to_bv()
        log.warn(f"Assigned placeholder {res}")
        return res

    def typed_value_const(self, **kwargs):
        # User wants to provide their own value
        res = input("( hex ) > ")
        res = int(res, 16)
        log.warn(f"Using user-provided value {res:x}")
        return res

    def typed_value_null(self, **kwargs):
        log.warn("Using NULL")
        return 0

    def typed_value_ignore(self, default=None, **kwargs):
        if default is None:
            log.warn("Will use default when determined.")
        elif isinstance(default, int):
            log.warn(f"Using default {default:x}")
        else:
            log.warn(f"Using default {default}")
        return default

    def typed_value_stop(self, **kwargs):
        log.warn("Stopping execution path")
        raise PathTerminationSignal()

    def typed_value_quit(self, **kwargs):
        log.warn("Aborting execution")
        quit()

    def untyped_value_ignore(self, default=None, **kwargs):
        if default is None:
            log.warn("Will use default when generated")
        elif isinstance(default, int):
            log.warn(f"Using default value {default:x}")
        else:
            log.warn(f"Using default value {default}")
        return default

    def untyped_reg_bind(**kwargs):
        raise NotImplementedError("Type binding not implemented for registers")

    def untyped_addr_bind(**kwargs):
        raise NotImplementedError("Type binding not implemented for addresses")

    def untyped_sym_bind(**kwargs):
        raise NotImplementedError("Type binding not implemented for symbols")

    def untyped_value_stop(self, **kwargs):
        self.warn("Stopping self execution path")
        raise PathTerminationSignal()

    def untyped_value_quit(self, **kwargs):
        log.warn("Aborting execution")
        quit()
