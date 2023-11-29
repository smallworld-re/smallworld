from angr.storage.memory_mixins import MemoryMixin
from .base import BaseMemoryMixin
from .terminate import PathTerminationSignal
from .typedefs import PointerDef, StructDef
from .visitor import EvalVisitor
from .utils import print_state
from ..utils.tui import SimpleTUI, TUIContinueException
import claripy


visitor = EvalVisitor()


class ModelMemoryMixin(BaseMemoryMixin):
    """
    Mixin for detecting model violations in memory ops.
    """

    def _setup_tui(self):
        super()._setup_tui()
        self.typed_value_tui = SimpleTUI()
        self.typed_value_tui.add_case(
            "alloc", self.typed_value_alloc, hint="Allocate a new instance"
        )
        self.typed_value_tui.add_case(
            "reuse", self.typed_value_reuse, hint="Reuse an existing instance"
        )
        self.typed_value_tui.add_case(
            "placeholder", self.typed_value_placeholder, hint="Use a placeholder symbol"
        )
        self.typed_value_tui.add_case(
            "const", self.typed_value_const, hint="Provide a constant value"
        )
        self.typed_value_tui.add_case("null", self.typed_value_null, hint="Use NULL")
        self.typed_value_tui.add_case(
            "ignore", self.typed_value_ignore, hint="Use default from angr"
        )
        self.typed_value_tui.add_case(
            "details", self.typed_value_details, hint="Print details of current state"
        )
        self.typed_value_tui.add_case(
            "stop", self.typed_value_stop, hint="Kill current execution path"
        )
        self.typed_value_tui.add_case(
            "quit", self.typed_value_quit, hint="Exit the analyzer"
        )

        self.untyped_reg_tui = SimpleTUI()
        self.untyped_reg_tui.add_case(
            "ignore", self.untyped_value_ignore, hint="Use default from angr"
        )
        self.untyped_reg_tui.add_case(
            "bind", self.untyped_reg_bind, hint="Create a type binding and initialize"
        )
        self.untyped_reg_tui.add_case(
            "details", self.untyped_reg_details, hint="Print details of current state"
        )
        self.untyped_reg_tui.add_case(
            "stop", self.untyped_value_stop, hint="Kill current execution path"
        )
        self.untyped_reg_tui.add_case(
            "quit", self.untyped_value_quit, hint="Exit the analyzer"
        )

        self.untyped_addr_tui = SimpleTUI()
        self.untyped_addr_tui.add_case(
            "ignore", self.untyped_value_ignore, hint="Use default from angr"
        )
        self.untyped_addr_tui.add_case(
            "bind", self.untyped_addr_bind, hint="Create a type binding and initialize"
        )
        self.untyped_addr_tui.add_case(
            "details", self.untyped_addr_details, hint="Print details of current state"
        )
        self.untyped_addr_tui.add_case(
            "stop", self.untyped_value_stop, hint="Kill current execution path"
        )
        self.untyped_addr_tui.add_case(
            "quit", self.untyped_value_quit, hint="Exit the analyzer"
        )

        self.untyped_sym_tui = SimpleTUI()
        self.untyped_sym_tui.add_case(
            "ignore", self.untyped_value_ignore, hint="Use default from angr"
        )
        self.untyped_sym_tui.add_case(
            "bind", self.untyped_sym_bind, hint="Create a type binding and initialize"
        )
        self.untyped_sym_tui.add_case(
            "details", self.untyped_sym_details, hint="Print details of current state"
        )
        self.untyped_sym_tui.add_case(
            "stop", self.untyped_value_stop, hint="Kill current execution path"
        )
        self.untyped_sym_tui.add_case(
            "quit", self.untyped_value_quit, hint="Exit the analyzer"
        )

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
        if isinstance(typedef, PointerDef):
            default = "alloc"
            disabled = set()
        else:
            default = "placeholder"
            disabled = {"alloc", "reuse"}
        return self.typed_value_tui.handle(
            default, disabled, typedef=typedef, default=default, pretty=pretty
        )

    def _handle_untyped_register(self, reg_name, default):
        return self.untyped_reg_tui.handle(
            "ignore", set(), reg_name=reg_name, default=default
        )

    def _handle_untyped_address(self, addr, default):
        return self.untyped_addr_tui.handle("ignore", set(), addr=addr, default=default)

    def _handle_untyped_symbol(self, sym_name, default):
        return self.untyped_sym_tui.handle(
            "ignore", set(), sym_name=sym_name, default=default
        )

    def _default_value(self, addr, size, **kwargs):
        environ = self.state.typedefs
        res = super()._default_value(addr, size, **kwargs)
        if self.id == "reg":
            reg_name = self.state.arch.register_size_names[(addr, size)]
            reg_def = environ.get_register_binding(reg_name)
            if reg_def is not None:
                # TODO: Ask the user what we should do.
                # 'alloc' is the default action,
                # but there are a few more:
                # - NULL this allocation
                # - use an existing allocation
                # - ignore this fork; it's a recurisve/boring case
                # - abort execution; something's wrong here.
                self.log.warn(f"Register {reg_name} has type {reg_def}, but no value")
                self.log.warn("What do you want to do about it?")
                res = self._handle_typed_value(reg_def, res, reg_name)
            else:
                self.log.warn(f"Register {reg_name} has no type")
                self.log.warn("What do you want to do about it?")
                res = self._handle_untyped_register(reg_name, res)
            if isinstance(res, int):
                res = self.state.solver.BVV(res, size * 8)
        else:
            addr_def = environ.get_address_binding(addr)
            if addr_def is not None:
                self.log.warn(f"Address {addr:x} has type {addr_def}, but no value")
                self.log.warn("What do you want to do about it?")
                res = self._handle_typed_value(addr_def, res, addr)
            else:
                self.log.warn(f"Address {addr:x} has no type")
                self.log.warn("What do you want to do about it?")
                self._handle_untyped_address(addr, res)

        return res

    def _concretize_bindings(self, supercall, addr, strategies, condition):
        """
        Concretization strategy for interrogating model

        This is the same code for both reads and writes.
        """
        environ = self.state.typedefs

        self.log.debug(f"\tAddr:       {addr}")
        bindings = dict()
        complete = True
        for v in filter(lambda x: x.op == "BVS", addr.leaf_asts()):
            value = environ.get_symbol(v.args[0])
            if value is None:
                binding = environ.get_symbol_binding(v.args[0])
                if binding is None:
                    self.log.warn(
                        f"Symbol {v} (part of address expression {addr}) has no type"
                    )
                    self.log.warn("What do you want to do about it?")
                    value = self._handle_untyped_symbol(v, None)
                    if value is None:
                        complete = False
                        continue
                else:
                    self.log.warn(
                        f"Symbol {v} (part of address expression {addr}) has type {binding}, but no value"
                    )
                    self.log.warn("What do you want to do about it?")
                    while True:
                        value = self._handle_typed_value(binding, None, addr)
                        if value is not None and not self.state.solver.satisfiable(
                            extra_constraints=[v == value]
                        ):
                            self.log.warn(
                                f"Selection {value:x} is not valid; please try again"
                            )
                            continue
                        break
                    if value is None:
                        complete = False
                        continue
                environ.set_symbol(v.args[0], value)
                self.log.debug(f"\tNew Valuei for {v.args[0]}: {value:x}")
            else:
                self.log.debug(f"\tExisting Value for {v.args[0]}: {value:x}")
            bindings[v.args[0]] = claripy.BVV(value, 64)
        if complete:
            value = visitor.visit(addr, bindings=bindings)
            if not isinstance(value, int):
                value = value.concrete_value
            res = [value]
        else:
            res = supercall(addr, strategies=strategies, condition=condition)
        self.log.debug("\tResults:")
        for v in res:
            if isinstance(v, int):
                self.log.debug(f"\t\t{v:x}")
            else:
                self.log.debug(f"\t\t{v}")
        return res

    def concretize_read_addr(self, addr, strategies=None, condition=None):
        self.log.debug("Concretizing on read:")
        return self._concretize_bindings(
            super().concretize_read_addr, addr, strategies, condition
        )

    def concretize_write_addr(self, addr, strategies=None, condition=None):
        self.log.debug("Concretizing on write:")
        return self._concretize_bindings(
            super().concretize_write_addr, addr, strategies, condition
        )

    # TUI handler functions.  Fear the boilerplate.

    def typed_value_alloc(self, typedef=None, **kwargs):
        # User wants to allocate a new instance
        environ = self.state.typedefs
        res = environ.allocate(typedef)
        self.log.warn(f"Allocated {len(typedef._kind)} bytes at {res:x}")
        return res

    def typed_value_reuse(self, typedef=None, **kwargs):
        # User wants to reuse an instance
        environ = self.state.typedefs
        options = environ.get_allocs_for_type(typedef)
        if len(options) == 0:
            # No allocations for self data type.  Derp.
            self.log.warn("No reusable values available in self state")
            raise TUIContinueException()
        choice = None
        # TODO: capture self in a TUI.
        # This is weird, since the list of options changes a lot.
        while True:
            # Mini-repl to ask them to pick one.
            self.log.warn("Choices:")
            idx = 1
            for addr in options:
                self.log.warn(f"{idx}: {addr:x}")
                if isinstance(typedef._kind, StructDef):
                    fields = typedef._kind.get_fields(self.state, addr)
                    for addr, name, expr in fields:
                        value = None
                        if expr.op == "bvs":
                            value = environ.get_symbol(expr.args[0])
                        if value is not None:
                            self.log.warn(f"\t{addr:x}: {name} = {expr} -> {value:x}")
                        else:
                            self.log.warn(f"\t{addr:x}: {name} = {expr} -> (no value)")
                else:
                    self.log.warn("\t(Not a struct)")
                idx += 1
            choice = input(f"( 1 - {idx - 1} | Back ) >").lower()
            if choice == "back" or choice == "b":
                # User doesn't like the choices.  Go back to main loop
                choice = None
                break
            try:
                choice = int(choice)
                if choice < 1 or choice >= idx:
                    self.log.error(
                        f"Invalid choice {choice}; must be between 1 and {idx - 1}"
                    )
                    continue
                # Convert from 1-indexed to 0-indexed
                choice -= 1
                break
            except:
                self.log.error(f"Invalid choice {choice}")
                continue
        if choice is None:
            # User didn't like the choices; go back to main loop
            raise TUIContinueException()
        self.log.warn(
            "Reusing value from {options[choice][0]} -> {options[choice][1]:x}"
        )
        return options[choice]

    def typed_value_placeholder(self, typedef=None, **kwargs):
        # User wants to assign a placeholder symbol, not a real value.
        res = typedef.to_bv()
        self.log.warn(f"Assigned placeholder {res}")
        return res

    def typed_value_const(self, **kwargs):
        # User wants to provide their own value
        res = input("( hex ) > ")
        res = int(res, 16)
        self.log.warn(f"Using user-provided value {res:x}")
        return res

    def typed_value_null(self, **kwargs):
        self.log.warn("Using NULL")
        return 0

    def typed_value_ignore(self, default=None, **kwargs):
        if default is None:
            self.log.warn("Will use default when determined.")
        elif isinstance(default, int):
            self.log.warn("Using default {default:x}")
        else:
            self.log.warn("Using default {default}")
        return default

    def typed_value_details(self, typedef=None, default=None, pretty=None):
        environ = self.state.typedefs
        self.log.warn("Details of missing value at {self.state.ip}:")
        print_state(self.log.warn, self.state, "typed nwbt")
        self.log.warn(f"Missing value: {pretty}")
        self.log.warn(f"Typedef: {typedef}")
        self.log.warn(f"Default: {default}")
        if isinstance(typedef, PointerDef) and isinstance(typedef._kind, StructDef):
            self.log.warn("Available Instances:")
            options = environ.get_allocs_for_type(typedef)
            for addr in options:
                self.log.warn(f"- {addr:x}")
                fields = typedef._kind.get_fields(self.state, addr)
                for addr, name, expr in fields:
                    value = None
                    if expr.op == "bvs":
                        value = environ.get_symbol(expr.args[0])
                    if value is not None:
                        self.log.warn(f"\t{addr:x}: {name:16s} = {expr} -> {value:x}")
                    else:
                        self.log.warn(f"\t{addr:x}: {name:16s} = {expr} -> (no value)")
        raise TUIContinueException()

    def typed_value_stop(self, **kwargs):
        self.log.warn("Stopping execution path")
        raise PathTerminationSignal()

    def typed_value_quit(self, **kwargs):
        self.log.warn("Aborting execution")
        quit()

    def untyped_value_ignore(self, default=None, **kwargs):
        if default is None:
            self.log.warn("Will use default when generated")
        elif isinstance(default, int):
            self.log.warn("Using default value {default:x}")
        else:
            self.log.warn("Using default value {default}")
        return default

    def untyped_reg_bind(**kwargs):
        raise NotImplementedError("Type binding not implemented for registers")

    def untyped_addr_bind(**kwargs):
        raise NotImplementedError("Type binding not implemented for addresses")

    def untyped_sym_bind(**kwargs):
        raise NotImplementedError("Type binding not implemented for symbols")

    def untyped_reg_details(self, reg_name=None, default=None, **kwargs):
        self.log.warn("Details of untyped register at {self.state.ip}")
        print_state(self.log.warn, self.state, "untyped nwbt")
        self.log.warn(f"Register: {reg_name}")
        self.log.warn(f"Default:  {default}")
        raise TUIContinueException()

    def untyped_addr_details(self, addr=None, default=None, **kwargs):
        self.log.warn("Details of untyped address at {self.state.ip}")
        print_state(self.log.warn, self.state, "untyped nwbt")
        self.log.warn(f"Address:  {addr:x}")
        self.log.warn(f"Default:  {default}")
        raise TUIContinueException()

    def untyped_sym_details(self, sym_name=None, default=None, **kwargs):
        self.log.warn("Details of untyped symbol at {self.state.ip}")
        print_state(self.log.warn, self.state, "untyped nwbt")
        self.log.warn(f"Symbol:   {sym_name}")
        self.log.warn(f"Default:  {default}")
        raise TUIContinueException()

    def untyped_value_stop(self, **kwargs):
        self.warn("Stopping self execution path")
        raise PathTerminationSignal()

    def untyped_value_quit(self, **kwargs):
        self.log.warn("Aborting execution")
        quit()
