import logging
import typing

import angr
import claripy

from ... import analyses, emulators, exceptions, hinting, platforms, state
from ...emulators.angr.exceptions import PathTerminationSignal
from .. import forced_exec, underlays
from .guards import GuardTrackingScratchPlugin
from .hints import (
    ClaripySerializable,
    FieldEventHint,
    PartialBitFieldAccessHint,
    PartialByteFieldAccessHint,
    PartialByteFieldWriteHint,
    TrackedFieldHint,
    UnknownFieldHint,
)

log = logging.getLogger(__name__)
hinter = hinting.get_hinter(__name__)

# Tell angr to be quiet please
logging.getLogger("angr").setLevel(logging.WARNING)


class FDAState:
    def __init__(self):
        self.fda_labels = set()
        self.fda_addr_to_label = dict()
        self.fda_label_to_addr = dict()
        self.fda_mem_ranges = set()
        self.fda_bindings = dict()
        self.fda_byte_labels = set()
        self.fda_addr_to_unk_label = dict()


class FieldDetectionMixin(underlays.AnalysisUnderlay):
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

    halt_on_hint = True

    def translate_global_addr(self, fda, addr):
        # Convert address into a label
        for r, label in fda.fda_addr_to_label.items():
            if addr in r:
                return label
        return "UNKNOWN"

    def add_unk_label(self, emu, fda, addr, expr):
        size = len(expr) // 8
        r = range(addr, addr + size)
        label = f"UNK.{hex(addr)}"
        sym = claripy.BVS(f"UNK.{hex(addr)}", size * 8)
        emu.add_constraint(sym == expr)

        fda.fda_addr_to_unk_label[r] = label
        return sym

    def mem_read_hook(self, emu, addr, size, expr):
        fda = emu.get_extension("fda")
        cheat = self.translate_global_addr(fda, addr)
        log.warning(
            f"{hex(emu.state._ip.concrete_value)}: READING {hex(addr)} - {hex(addr + size)} ({cheat})"
        )
        log.warning(f"  {expr}")

        r = range(addr, addr + size)
        if r in fda.fda_addr_to_unk_label:
            log.warning("  Read from already-hinted field")
            return None

        if expr.op == "Reverse":
            # Bytes are reversed.
            # angr's memory is big-endian,
            # and the program interpreted it as a little-endian value.
            expr = expr.args[0]

        if expr.op == "BVV":
            # This is a concrete value.  These are safe
            return None

        if expr.op == "BVS":
            # This is a symbol.  It's okay if it's a field, or an UNK field
            label = expr.args[0].split("_")[0]
            if label in fda.fda_labels or label.startswith("UNK."):
                return

            hint = UnknownFieldHint(
                pc=emu.read_register("pc"),
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
            hinter.info(hint)
            if self.halt_on_hint:
                raise PathTerminationSignal()
            else:
                self.add_unk_label(emu, fda, addr, expr)
                return None

        if expr.op == "Extract":
            # This is a slice of another expression.
            if expr.args[2].op == "BVS":
                # This is a slice of a symbol, which means
                # the program read part of a field we labeled.
                # Dollars to ducats this means our labeling isn't precise enough.
                var = expr.args[2]
                label = var.args[0].split("_")[0]

                if var.args[0] not in fda.fda_labels:
                    # This is not a label we know
                    hint = UnknownFieldHint(
                        pc=emu.read_register("pc"),
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
                    r = fda.fda_label_to_addr[var.args[0]]
                    field_size = r.stop - r.start
                    start = field_size * 8 - start - 1
                    end = field_size * 8 - end

                    if start % 8 != 0 or end % 8 != 0:
                        hint = PartialBitFieldAccessHint(
                            pc=emu.read_register("pc"),
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
                            pc=emu.read_register("pc"),
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
                if self.halt_on_hint:
                    raise PathTerminationSignal()
                else:
                    self.add_unk_label(emu, fda, addr, expr)
                    return None

        # This is a complex expression.
        # We're accessing the results of a computation
        hint = UnknownFieldHint(
            pc=emu.read_register("pc"),
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
        hinter.info(hint)
        if self.halt_on_hint:
            raise PathTerminationSignal()
        else:
            self.add_unk_label(emu, fda, addr, expr)
            return None

    def mem_write_hook(self, emu, addr, size, expr):
        fda = emu.get_extension("fda")
        cheat = self.translate_global_addr(fda, addr)
        log.warning(
            f"{hex(emu.state._ip.concrete_value)}: WRITING {hex(addr)} - {hex(addr + size)} ({cheat})"
        )
        log.warning(f"  {expr}")

        good = False
        bad = False

        r = range(addr, addr + size)
        if r in fda.fda_addr_to_unk_label:
            label = fda.fda_addr_to_unk_label[r]
            log.warning(f"  Write to already-hinted field {label}")
            sym = claripy.BVS(label, size * 8)
            emu.add_constraint(sym == expr)
            emu.state.inspect.mem_write_expr = sym

            return

        for r, label in fda.fda_addr_to_label.items():
            if addr in r:
                # Write is within an existing field
                if r.start == addr and r.stop == addr + size:
                    # Write lines up with the existing field.
                    # Create a new symbol for the new def of this field.
                    log.warning(f"  Write to entire field {cheat}")
                    sym = claripy.BVS(label, size * 8)
                    emu.add_constraint(sym == expr)
                    emu.state.inspect.mem_write_expr = sym
                    fda.fda_bindings[sym.args[0]] = expr
                    good = True
                else:
                    # Write does not line up with the existing field
                    start = addr - r.start
                    end = addr + size - r.start
                    hint = PartialByteFieldWriteHint(
                        pc=emu.read_register("pc"),
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
            raise exceptions.ConfigurationError("Overlapping labels")
        elif bad:
            if self.halt_on_hint:
                raise PathTerminationSignal()
            else:
                sym = self.add_unk_label(emu, fda, addr, expr)
                emu.state.inspect.mem_write_expr = sym
                return
        elif good:
            return
        else:
            # Write doesn't overlap any known fields
            hint = UnknownFieldHint(
                pc=emu.read_register("pc"),
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
            if self.halt_on_hint:
                raise PathTerminationSignal()
            else:
                sym = self.add_unk_label(emu, fda, addr, expr)
                emu.state.inspect.mem_write_expr = sym
                return

    def angr_preinit(self, emu):
        preset = angr.SimState._presets["default"].copy()
        preset.add_default_plugin("scratch", GuardTrackingScratchPlugin)
        emu._plugin_preset = preset

    def run(self, machine):
        # Set up the filter analysis
        fda = FDAState()
        filt = FieldDetectionFilter()
        filt.activate()

        # Set up the emulator

        machine.apply(self.emulator)
        self.emulator.add_extension("fda", fda)

        # Capture the labeled memory ranges
        for s in machine:
            if isinstance(s, state.memory.Memory):
                start = s.address
                end = start + s.get_capacity()
                log.warning(f"{hex(start)} - {hex(end)}")
                for off, val in s.items():
                    label = val.get_label()
                    if label is not None:
                        # This is a labeled value.  It represents a field we want to track.
                        val_start = start + off
                        val_end = val_start + val.get_size()
                        log.warning(
                            f"  {hex(val_start)} - {hex(val_end)}: {val} := {label}"
                        )
                        hint = TrackedFieldHint(
                            message="Tracking new field",
                            address=val_start,
                            size=val.get_size(),
                            label=label,
                        )
                        hinter.info(hint)

                        if label in fda.fda_labels:
                            log.error(
                                f"You reused label {label}; please give it a unique name"
                            )
                            raise exceptions.ConfigurationError("Duplicate field name")

                        r = range(val_start, val_end)
                        fda.fda_labels.add(label)
                        fda.fda_addr_to_label[r] = label
                        fda.fda_label_to_addr[label] = r
                        fda.fda_bindings[label] = claripy.BVS(
                            label, val.get_size() * 8, explicit_name=True
                        )
                        fda.fda_mem_ranges.add((val_start, val_end))

        for start, end in fda.fda_mem_ranges:
            self.emulator.hook_memory_read_symbolic(start, end, self.mem_read_hook)
            self.emulator.hook_memory_write_symbolic(start, end, self.mem_write_hook)

        self.execute()

        log.warning(self.emulator.mgr)
        log.warning(self.emulator.mgr.errored)

        def state_visitor(emu: emulators.Emulator) -> None:
            if not isinstance(emu, emulators.AngrEmulator):
                raise TypeError(type(emu))
            fda = emu.get_extension("fda")
            for start, end in fda.fda_mem_ranges:
                emu.unhook_memory_read(start, end)
                emu.unhook_memory_write(start, end)

            log.warning(f"State at {emu.state._ip}:")
            log.warning("  Guards:")
            for ip, guard in emu.state.scratch.guards:
                if guard.op == "BoolV":
                    continue
                log.warning(f"    {hex(ip)}: {guard}")
            log.warning("  Fields:")
            for r in fda.fda_addr_to_label:
                val = emu.state.memory.load(r.start, r.stop - r.start)
                if len(val.variables) == 1:
                    # val is extremely likely a bound symbol.
                    # Fetch the binding
                    (label,) = val.variables
                    if label in fda.fda_bindings:
                        val = fda.fda_bindings[label]
                    else:
                        log.error(f"  Unknown variable {label}")

                log.warning(f"    {hex(r.start)} - {hex(r.stop)}: {label} = {val}")

        self.emulator.visit_states(state_visitor, stash="deadended")
        filt.deactivate()


class FieldDetectionFilter(analyses.Filter):
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

    def analyze(self, hint: hinting.Hint):
        # Step 0: Print hints in a sane format.
        # The raw hint logging is unreadable.
        if not isinstance(hint, FieldEventHint):
            return
        hint.pp(log.error)

        if isinstance(hint, PartialByteFieldAccessHint):
            # Step 1: If this is a field access, remember it for later
            field = (hint.start, hint.end)
            self.partial_ranges.setdefault(hint.label, dict()).setdefault(
                field, list()
            ).append(hint)

    def activate(self):
        self.listen(FieldEventHint, self.analyze)

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


class FieldDetectionAnalysis(FieldDetectionMixin, underlays.BasicAnalysisUnderlay):
    """Detect fields on full path exploration"""

    name = "Field Detection Analysis"
    version = "0.0"
    description = "Detects discrepancies between labels and field accesses"

    def __init__(self, platform: platforms.Platform):
        self.platform = platform
        self.emulator = emulators.AngrEmulator(self.platform, preinit=self.angr_preinit)


class ForcedFieldDetectionAnalysis(
    FieldDetectionMixin, forced_exec.ForcedExecutionUnderlay
):
    name = "Field Detection Analysis - Forced"
    version = "0.0"
    description = "Detects discrepancies between labels and field accesses"

    halt_on_hint = False

    def __init__(
        self, platform: platforms.Platform, trace: typing.List[typing.Dict[str, int]]
    ):
        self.platform = platform
        self.emulator = emulators.AngrEmulator(self.platform, preinit=self.angr_preinit)
        self.emulator.enable_linear()
        super().__init__(trace)
