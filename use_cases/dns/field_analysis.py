import dataclasses
import logging
import typing

import angr
import claripy
from guards import GuardTrackingScratchMixin

import smallworld
from smallworld.emulators.angr.exceptions import PathTerminationSignal

log = logging.getLogger(__name__)
hinter = smallworld.hinting.get_hinter(__name__)

# Tell angr to be quiet please
logging.getLogger("angr").setLevel(logging.WARNING)


class FDAScratchPlugin(
    GuardTrackingScratchMixin, smallworld.emulators.angr.scratch.ExpandedScratchPlugin
):
    """angr scratch plugin that remembers path guards, and analysis state"""

    def __init__(self, scratch=None):
        super().__init__(scratch=scratch)
        self.fda_labels = set()
        self.fda_addr_to_label = dict()
        self.fda_label_to_addr = dict()
        self.fda_mem_ranges = set()
        self.fda_bindings = dict()

        if scratch is not None:
            self.fda_labels |= scratch.fda_labels
            self.fda_addr_to_label.update(scratch.fda_addr_to_label)
            self.fda_label_to_addr.update(scratch.fda_label_to_addr)
            self.fda_mem_ranges.update(scratch.fda_mem_ranges)
            self.fda_bindings.update(scratch.fda_bindings)


class ClaripySerializable(smallworld.hinting.hinting.Serializable):
    """Serializable wrapper that allows serializing claripy expressions in hints."""

    @classmethod
    def claripy_to_dict(cls, expr):
        if (
            expr is None
            or isinstance(expr, int)
            or isinstance(expr, str)
            or isinstance(expr, bool)
        ):
            return expr
        else:
            return {"op": expr.op, "args": list(map(cls.claripy_to_dict, expr.args))}

    def __init__(self, expr):
        self.expr = expr

    def to_dict(self):
        return self.claripy_to_dict(self.expr)

    @classmethod
    def from_dict(cls, dict):
        raise NotImplementedError(
            "Rebuilding clairpy is a lot harder than tearing it apart"
        )


@dataclasses.dataclass(frozen=True)
class FieldHint(smallworld.hinting.Hint):
    """Hint representing a detected, unhandled field"""

    pc: int = 0
    guards: typing.List[typing.Tuple[int, ClaripySerializable]] = dataclasses.field(
        default_factory=list
    )
    address: int = 0
    size: int = 0
    access: str = ""

    def pp(self, out):
        out(self.message)
        out(f"  pc:         {hex(self.pc)}")
        out(f"  address:    {hex(self.address)}")
        out(f"  size:       {self.size}")
        out(f"  access:     {self.access}")
        out("  guards:")
        for pc, guard in self.guards:
            out(f"    {hex(pc)}: {guard.expr}")


@dataclasses.dataclass(frozen=True)
class UnknownFieldHint(FieldHint):
    """Hint representing an access of an unknown field.

    The expression loaded from memory is not
    a simple slice of any known label.
    """

    message: str = "Accessed unknown field"  # Don't need to replace
    expr: str = ""

    def pp(self, out):
        super().pp(out)
        out(f"  expr:       {self.expr}")


@dataclasses.dataclass(frozen=True)
class PartialByteFieldAccessHint(FieldHint):
    """Hint representing an access to part of a known field."""

    message: str = "Partial access to known field"  # Don't need to replace
    label: str = ""
    start: int = 0
    end: int = 0

    def pp(self, out):
        super().pp(out)
        out(f"  field:      {self.label}[{self.start}:{self.end}]")


@dataclasses.dataclass(frozen=True)
class PartialByteFieldWriteHint(PartialByteFieldAccessHint):
    """Hint representing a write to part of a known field.

    Also includes the data I'm trying to write
    """

    message: str = "Partial write to known field"  # Don't need to replace
    access: str = "write"  # Don't need to replace
    expr: str = ""

    def pp(self, out):
        super().pp(out)
        out(f"  expr:       {self.expr}")


@dataclasses.dataclass(frozen=True)
class PartialBitFieldAccessHint(FieldHint):
    """Hint representing an access to a bit field within a known field."""

    message: str = "Bit field access in known field"  # Don't need to replace
    label: str = ""
    start: int = 0
    end: int = 0

    def pp(self, out):
        super().pp(out)
        out(f"  field:      {self.label}[{self.start}:{self.end}]")


class FieldDetectionAnalysis(smallworld.analyses.Analysis):
    """Analysis comparing state labels to field accesses.

    This assumes that memory labels correspond to fields
    of a structure, or a struct-coded buffer.

    The hypothesis is that any memory accesses that don't correspond
    to a defined field mean that your understanding of
    the as-implemented program is incorrect.

    This is an initial experiment,
    but the goal is to either help lift data formats,
    or compare a program against a known format.

    This approach works best against fixed-size binary data formats.
    It's got a limited ability to handle run-length-encoded formats
    by concretizing the run lengths.
    Attempting to handle a delimited or text-based format
    will likely lead to insanity.
    """

    name = "Field Detection Analysis"
    version = "0.0"
    description = "Detects discrepancies between labels and field accesses"

    def __init__(self, platform: smallworld.platforms.Platform):
        self.platform = platform
        self.extra_constraints: typing.List[typing.Tuple[int, str, str, int]] = list()

    def set_extra_constraints(
        self, cons: typing.List[typing.Tuple[int, str, str, int]]
    ):
        """Inject extra constraints into the initial angr state"""
        self.extra_constraints = list()
        for size, label, op, val in cons:
            size = size * 8
            sym = claripy.BVS(label, size, explicit_name=True)
            val = claripy.BVV(val, size)
            if op == "eq":
                self.extra_constraints.append(sym == val)
            elif op == "ne":
                self.extra_constraints.append(sym != val)
            elif op == "gt":
                self.extra_constraints.append(sym > val)
            elif op == "ge":
                self.extra_constraints.append(sym >= val)
            elif op == "lt":
                self.extra_constraints.append(sym < val)
            elif op == "le":
                self.extra_constraints.append(sym <= val)
            else:
                raise smallworld.exceptions.ConfigurationError(
                    f"Unknown constraint operator {op}"
                )
            log.warn(f"Added constraint {self.extra_constraints[-1]}")

    def translate_global_addr(self, emu, addr):
        # Convert address into a label
        for r, label in emu.state.scratch.fda_addr_to_label.items():
            if addr in r:
                return label
        return "UNKNOWN"

    def mem_read_hook(self, emu, addr, size):
        expr = emu.state.inspect.mem_read_expr
        cheat = self.translate_global_addr(emu, addr)
        log.info(
            f"{hex(emu.state._ip.concrete_value)}: READING {hex(addr)} - {hex(addr + size)} ({cheat})"
        )
        log.info(f"  {expr}")

        if expr.op == "Reverse":
            # Bytes are reversed.
            # angr's memory is big-endian,
            # and the program interpreted it as a little-endian value.
            expr = expr.args[0]

        if expr.op == "BVV":
            # This is a concrete value.  These are safe
            return

        if expr.op == "BVS":
            # This is a symbol.  It's okay if it's a field.
            label = expr.args[0].split("_")[0]
            if label in emu.state.scratch.fda_labels:
                return
            hint = UnknownFieldHint(
                pc=emu.state._ip.concrete_value,
                guards=list(
                    map(
                        lambda x: (x[0], ClaripySerializable(x[1])),
                        filter(lambda x: x[1].op != "BoolV", emu.state.scratch.guards),
                    )
                ),
                address=addr,
                size=size,
                expr=str(expr),
            )
            raise PathTerminationSignal()

        if expr.op == "Extract":
            # This is a slice of another expression.
            if expr.args[2].op == "BVS":
                # This is a slice of a symbol, which means
                # the program read part of a field we labeled.
                # Dollars to ducats this means our labeling isn't precise enough.
                var = expr.args[2]
                label = var.args[0].split("_")[0]

                if var.args[0] not in emu.state.scratch.fda_labels:
                    # This is not a label we know
                    hint = UnknownFieldHint(
                        pc=emu.state._ip.concrete_value,
                        guards=list(
                            map(
                                lambda x: (x[0], ClaripySerializable(x[1])),
                                filter(
                                    lambda x: x[1].op != "BoolV",
                                    emu.state.scratch.guards,
                                ),
                            )
                        ),
                        address=addr,
                        size=size,
                        access="read",
                        expr=str(var),
                    )
                else:
                    # This is a partial read from a known field
                    start = expr.args[0]
                    end = expr.args[1]

                    # Angr's bit numbering is annoying.
                    r = emu.state.scratch.fda_label_to_addr[var.args[0]]
                    size = r.stop - r.start
                    start = size * 8 - start - 1
                    end = size * 8 - end

                    if start % 8 != 0 or end % 8 != 0:
                        hint = PartialBitFieldAccessHint(
                            pc=emu.state._ip.concrete_value,
                            guards=list(
                                map(
                                    lambda x: (x[0], ClaripySerializable(x[1])),
                                    filter(
                                        lambda x: x[1].op != "BoolV",
                                        emu.state.scratch.guards,
                                    ),
                                )
                            ),
                            address=addr,
                            size=size,
                            access="read",
                            label=var.args[0],
                            start=start,
                            end=end,
                        )
                    else:
                        hint = PartialByteFieldAccessHint(
                            pc=emu.state._ip.concrete_value,
                            guards=list(
                                map(
                                    lambda x: (x[0], ClaripySerializable(x[1])),
                                    filter(
                                        lambda x: x[1].op != "BoolV",
                                        emu.state.scratch.guards,
                                    ),
                                )
                            ),
                            address=addr,
                            size=size,
                            access="read",
                            label=var.args[0],
                            start=start // 8,
                            end=end // 8,
                        )
                hinter.info(hint)
                raise PathTerminationSignal()

        # This is a complex expression.
        # We're accessing the results of a computation
        hint = UnknownFieldHint(
            pc=emu.state._ip.concrete_value,
            guards=list(
                map(
                    lambda x: (x[0], ClaripySerializable(x[1])),
                    filter(lambda x: x[1].op != "BoolV", emu.state.scratch.guards),
                )
            ),
            address=addr,
            size=size,
            access="read",
            expr=str(expr),
        )
        log.info("Constraints:")
        for con in emu.state.solver.constraints:
            log.info(f"  Constraint {con}")
        hinter.info(hint)
        raise PathTerminationSignal()

    def mem_write_hook(self, emu, addr, size, data):
        expr = emu.state.inspect.mem_write_expr
        cheat = self.translate_global_addr(emu, addr)
        log.info(
            f"{hex(emu.state._ip.concrete_value)}: WRITING {hex(addr)} - {hex(addr + size)} ({cheat})"
        )
        log.info(f"  {expr}")

        good = False
        bad = False
        for r, label in emu.state.scratch.fda_addr_to_label.items():
            if addr in r:
                # Write is within an existing field
                if r.start == addr and r.stop == addr + size:
                    # Write lines up with the existing field.
                    # Create a new symbol for the new def of this field.
                    log.info(f"  Write to entire field {cheat}")
                    sym = claripy.BVS(label, size * 8)
                    emu.state.solver.add(sym == expr)
                    emu.state.inspect.mem_write_expr = sym
                    emu.state.scratch.fda_bindings[sym.args[0]] = expr
                    good = True
                else:
                    # Write does not line up with the existing field
                    start = addr - r.start
                    end = addr + size - r.start
                    hint = PartialByteFieldWriteHint(
                        pc=emu.state._ip.concrete_value,
                        guards=list(
                            map(
                                lambda x: (x[0], ClaripySerializable(x[1])),
                                filter(
                                    lambda x: x[1].op != "BoolV",
                                    emu.state.scratch.guards,
                                ),
                            )
                        ),
                        address=addr,
                        size=size,
                        label=label,
                        start=start,
                        end=end,
                        expr=str(expr),
                    )
                    hinter.info(hint)
                    bad = True
        if bad and good:
            log.error("Write was complete and partial; your labels overlap.")
            raise smallworld.exceptions.ConfigurationError("Overlapping labels")
        elif bad:
            raise PathTerminationSignal()
        elif good:
            return
        else:
            # Write doesn't overlap any known fields
            hint = UnknownFieldHint(
                pc=emu.state._ip.concrete_value,
                guards=list(
                    map(
                        lambda x: (x[0], ClaripySerializable(x[1])),
                        filter(lambda x: x[1].op != "BoolV", emu.state.scratch.guards),
                    )
                ),
                address=addr,
                size=size,
                access="write",
                expr=str(expr),
            )
            hinter.info(hint)
            raise PathTerminationSignal()

    def run(self, machine):
        # Set up the filter analysis
        filt = FieldDetectionFilter()
        filt.activate()

        # Set up the emulator
        def angr_preinit(emu):
            preset = angr.SimState._presets["default"].copy()
            preset.add_default_plugin("scratch", FDAScratchPlugin)
            emu._plugin_preset = preset

        emulator = smallworld.emulators.AngrEmulator(
            self.platform, preinit=angr_preinit
        )
        machine.apply(emulator)
        emulator.state.solver.add(*self.extra_constraints)

        # Capture the labeled memory ranges
        for s in machine:
            if isinstance(s, smallworld.state.memory.Memory):
                start = s.address
                end = start + s.get_capacity()
                log.info(f"{hex(start)} - {hex(end)}")
                for off, val in s.items():
                    label = val.get_label()
                    if label is not None:
                        # This is a labeled value.  It represents a field we want to track.
                        val_start = start + off
                        val_end = val_start + val.get_size()
                        log.info(
                            f"  {hex(val_start)} - {hex(val_end)}: {val} := {label}"
                        )

                        if label in emulator.state.scratch.fda_labels:
                            log.error(
                                f"You reused label {label}; please give it a unique name"
                            )
                            raise smallworld.exceptions.ConfigurationError(
                                "Duplicate field name"
                            )

                        r = range(val_start, val_end)
                        emulator.state.scratch.fda_labels.add(label)
                        emulator.state.scratch.fda_addr_to_label[r] = label
                        emulator.state.scratch.fda_label_to_addr[label] = r
                        emulator.state.scratch.fda_bindings[label] = claripy.BVS(
                            label, val.get_size() * 8, explicit_name=True
                        )
                        emulator.state.scratch.fda_mem_ranges.add((val_start, val_end))

        for start, end in emulator.state.scratch.fda_mem_ranges:
            emulator.hook_memory_read(start, end, self.mem_read_hook)
            emulator.hook_memory_write(start, end, self.mem_write_hook)

        try:
            while True:
                emulator.step()
        except smallworld.exceptions.EmulationStop:
            pass
        except Exception:
            log.exception("Got exception")

        log.warning(emulator.mgr)
        log.warning(emulator.mgr.errored)

        def state_visitor(emu: smallworld.emulators.Emulator) -> None:
            if not isinstance(emu, smallworld.emulators.AngrEmulator):
                raise TypeError(type(emu))
            for start, end in emu.state.scratch.fda_mem_ranges:
                emu.unhook_memory_read(start, end)
                emu.unhook_memory_write(start, end)

            log.info(f"State at {emu.state._ip}:")
            log.info("  Guards:")
            for ip, guard in emu.state.scratch.guards:
                if guard.op == "BoolV":
                    continue
                log.info(f"    {hex(ip)}: {guard}")
            log.info("  Fields:")
            for r in emu.state.scratch.fda_addr_to_label:
                val = emu.state.memory.load(r.start, r.stop - r.start)
                if len(val.variables) == 1:
                    # val is extremely likely a bound symbol.
                    # Fetch the binding
                    (label,) = val.variables
                    if label in emu.state.scratch.fda_bindings:
                        val = emu.state.scratch.fda_bindings[label]
                    else:
                        log.error(f"  Unknown variable {label}")

                log.info(f"    {hex(r.start)} - {hex(r.stop)}: {label} = {val}")

        emulator.visit_states(state_visitor, stash="deadended")
        filt.deactivate()


class FieldDetectionFilter(smallworld.analyses.Filter):
    """Secondary field definition analysis.

    This picks up patterns that aren't noticeable from any
    single field access detection.
    """

    name = "field-detection-filter"
    version = "0.0"
    description = ""

    def __init__(self):
        super().__init__()
        self.active = True
        self.partial_ranges = dict()

    def analyze(self, hint: smallworld.hinting.Hint):
        # Step 0: Print hints in a sane format.
        # The raw hint logging is unreadable.
        if not isinstance(hint, FieldHint):
            return
        hint.pp(log.error)

        if isinstance(hint, PartialByteFieldAccessHint):
            # Step 1: If this is a field access, remember it for later
            field = (hint.start, hint.end)
            self.partial_ranges.setdefault(hint.label, dict()).setdefault(
                field, list()
            ).append(hint)

    def activate(self):
        self.listen(FieldHint, self.analyze)

    def deactivate(self):
        super().deactivate()
        if not self.active:
            return
        self.active = False
        # Post-process results to detect trends we'd miss on single hints
        solver = claripy.solvers.Solver()

        for label, fields in self.partial_ranges.items():
            # Detect multiple fields at the same label/offset
            # Step 1: Collate the field info for this label
            fields_by_start = dict()
            for (start, end), hints in fields.items():
                guards = fields_by_start.setdefault(start, dict()).setdefault(
                    end, set()
                )
                for hint in hints:
                    # Unify all guards across all hints.
                    # I'm only going to care about pairwise matches.
                    guards.update(
                        map(lambda x: x.expr, map(lambda x: x[1], hint.guards))
                    )

            # Step 2: See if we actually have overlaps
            for start, rest in fields_by_start.items():
                if len(rest) > 1:
                    log.error(f"Multiple field defs starting at {label}[{start}]:")
                    for end, guards in rest.items():
                        log.error(f"    {label}[{start}:{end}]")

                    # Step 3: see if we can pinpoint the controlling variables
                    # The way angr works, two states will have compilmentary guards;
                    # guard vs !guard.  If we can find these expressions,
                    # we have a short list of known fields to consider
                    control_vars = set()
                    for a_end, a_guards in rest.items():
                        for b_end, b_guards in rest.items():
                            for a_guard in a_guards:
                                for b_guard in b_guards:
                                    # Forgive me, Prof. Sleator, for I have sinned...
                                    # I ran an SMT solver in a quadruple for-loop.
                                    if not solver.satisfiable([a_guard == b_guard]):
                                        control_vars.update(a_guard.variables)
                                        control_vars.update(b_guard.variables)
                    if len(control_vars) != 0:
                        log.error(
                            "  One or more of the following fields may control the format,"
                        )
                        log.error("  either as a flag, type code or length:")
                        for var in control_vars:
                            log.error(f"    {var}")
