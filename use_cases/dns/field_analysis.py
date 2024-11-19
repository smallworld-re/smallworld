import logging

import claripy

import smallworld
from smallworld.emulators.angr.exceptions import PathTerminationSignal

log = logging.getLogger(__name__)


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

    def run(self, machine):
        # Set up the emulator
        emulator = smallworld.emulators.AngrEmulator(self.platform)
        emulator.enable_linear()
        machine.apply(emulator)

        labels = set()
        addr_to_label = dict()
        label_to_addr = dict()
        mem_ranges = smallworld.utils.RangeCollection()
        bindings = dict()

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

                        if label in labels:
                            log.error(
                                f"You reused label {label}; please give it a unique name"
                            )
                            raise smallworld.exceptions.ConfigurationError(
                                "Duplicate field name"
                            )

                        r = range(val_start, val_end)
                        labels.add(label)
                        addr_to_label[r] = label
                        label_to_addr[label] = r
                        bindings[label] = claripy.BVS(
                            label, val.get_size(), explicit_name=True
                        )
                        mem_ranges.add_range((val_start, val_end))

        # Helper for converting an address into a known field
        def translate_global_addr(addr):
            # Convert address into a label
            for r, label in addr_to_label.items():
                if addr in r:
                    return label
            return "UNKNOWN"

        def mem_read_hook(emu, addr, size):
            expr = emu.state.inspect.mem_read_expr
            cheat = translate_global_addr(addr)
            log.warning(f"READING {hex(addr)} - {hex(addr + size)} ({cheat})")
            log.warning(f"  {expr}")

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
                if label in labels:
                    return
                log.error(f"Read of unknown field: {expr}")
                raise PathTerminationSignal()

            if expr.op == "Extract":
                # This is a slice of another expression.
                if expr.args[2].op == "BVS":
                    # This is a slice of a symbol, which means
                    # the program read part of a field we labeled.
                    # Dollars to ducats this means our labeling isn't precise enough.
                    var = expr.args[2]
                    label = var.args[0].split("_")[0]

                    if var.args[0] not in labels:
                        # This is not a label we know
                        log.error(f"Read from unknown field {var}")

                    start = expr.args[0]
                    end = expr.args[1]

                    # Angr's bit numbering is annoying.
                    r = label_to_addr[var.args[0]]
                    size = r.stop - r.start
                    start = size * 8 - start - 1
                    end = size * 8 - end
                    if start % 8 != 0 or end % 8 != 0:
                        log.error(f"Read from unknown bit field {var}[{start}:{end}]")
                    else:
                        log.error(f"Read from unknown field {var}[{start//8}:{end//8}]")
                    raise PathTerminationSignal()

            # This is a complex expression.
            # We're accessing the results of a computation
            log.error(f"Read of computed value: {expr}")
            raise PathTerminationSignal()

        def mem_write_hook(emu, addr, size, data):
            expr = emu.state.inspect.mem_write_expr
            cheat = translate_global_addr(addr)
            log.warning(f"WRITING {hex(addr)} - {hex(addr + size)} ({cheat})")
            log.warning(f"  {expr}")

            good = False
            bad = False
            for r, label in addr_to_label.items():
                if addr in r:
                    # Write is within an existing field
                    if r.start == addr and r.stop == addr + size:
                        # Write lines up with the existing field.
                        # Create a new symbol for the new def of this field.
                        log.warn(f"Write to entire field {cheat}")
                        sym = claripy.BVS(label, size * 8)
                        emu.state.solver.add(sym == expr)
                        emu.state.inspect.mem_write_expr = sym
                        bindings[sym.args[0]] = expr
                        good = True
                    else:
                        # Write does not line up with the existing field
                        start = addr - r.start
                        end = addr + size - r.start

                        log.error(f"Write to part of field {cheat}[{start}:{end}]")
                        bad = True
            if bad and good:
                log.error("Write was complete and partial; your labels overlap.")
                raise PathTerminationSignal()
            if bad:
                raise PathTerminationSignal()
            if good:
                return

            # Write is to an unknown field within a tracked memory region.
            log.error("Write to an unknown field")
            raise PathTerminationSignal()

        for start, end in mem_ranges.ranges:
            emulator.hook_memory_read(start, end, mem_read_hook)
            emulator.hook_memory_write(start, end, mem_write_hook)

        try:
            while True:
                emulator.step()
        except smallworld.exceptions.EmulationStop:
            pass
        except Exception:
            log.exception("Got exception")

        for start, end in mem_ranges.ranges:
            emulator.unhook_memory_read(start, end)
            emulator.unhook_memory_write(start, end)

        print(emulator.mgr)
        print(emulator.mgr.errored)
        for r, label in addr_to_label.items():
            val = emulator.state.memory.load(r.start, r.stop - r.start)
            if len(val.variables) == 1:
                # val is extremely likely a bound symbol.
                # Fetch the binding
                (label,) = val.variables
                if label in bindings:
                    val = bindings[label]
                else:
                    log.error(f"Unknown variable {label}")

            log.warning(f"{hex(r.start)} - {hex(r.stop)}: {label} = {val}")
