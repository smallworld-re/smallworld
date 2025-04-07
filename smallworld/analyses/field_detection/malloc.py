import logging
import typing

import claripy

from ... import emulators, exceptions, platforms, state
from ...emulators.angr.exceptions import PathTerminationSignal

log = logging.getLogger(__name__)


class MallocModel(state.models.Model):
    name = "malloc"
    platform = platforms.Platform(
        platforms.Architecture.X86_64, platforms.Byteorder.LITTLE
    )
    abi = platforms.ABI.SYSTEMV

    _arg1_for_arch = {
        platforms.Architecture.AARCH64: "x0",
        platforms.Architecture.ARM_V5T: "r0",
        platforms.Architecture.ARM_V7A: "r0",
        platforms.Architecture.MIPS32: "a0",
        platforms.Architecture.MIPS64: "a0",
        platforms.Architecture.POWERPC32: "r3",
        platforms.Architecture.X86_64: "rdi",
    }

    _ret_for_arch = {
        platforms.Architecture.AARCH64: "x0",
        platforms.Architecture.ARM_V5T: "r0",
        platforms.Architecture.ARM_V7A: "r0",
        platforms.Architecture.MIPS32: "v0",
        platforms.Architecture.MIPS64: "v0",
        platforms.Architecture.POWERPC32: "r3",
        platforms.Architecture.X86_64: "rax",
    }

    def __init__(
        self,
        address: int,
        heap: state.memory.heap.Heap,
        platform: platforms.Platform,
        read_callback,
        write_callback,
    ):
        super().__init__(address)

        self.arg1_reg = self._arg1_for_arch[platform.architecture]
        self.ret_reg = self._ret_for_arch[platform.architecture]

        if len(heap) > 0:
            raise exceptions.ConfigurationError("This only works with a blank heap")
        end = state.IntegerValue(heap.address + heap.get_capacity(), 8, None)
        ptr = state.IntegerValue(heap.address + 16, 8, None)

        heap.allocate(end)
        heap.allocate(ptr)

        self.heap_addr = heap.address
        self.read_callback = read_callback
        self.write_callback = write_callback

        self.struct_lengths: typing.Dict[str, int] = dict()
        self.struct_prefixes: typing.Dict[str, str] = dict()
        self.struct_fields: typing.Dict[
            str, typing.List[typing.Tuple[int, str]]
        ] = dict()

    def bind_length_to_struct(
        self, field: str, prefix: str, labels: typing.List[typing.Tuple[int, str]]
    ):
        self.struct_lengths[field] = 0
        self.struct_prefixes[field] = prefix
        for size, label in labels:
            self.struct_lengths[field] += size
        self.struct_fields[field] = labels

    def model(self, emulator: emulators.Emulator):
        if not isinstance(emulator, emulators.AngrEmulator):
            raise exceptions.ConfigurationError("Model only works with angr")
        # Read the capacity.
        # Bypass the smallworld API; I want to know if it's symbolic
        fda = emulator.get_extension("fda")
        capacity = emulator.read_register_symbolic(self.arg1_reg)
        length = 0

        if capacity.symbolic:
            # Capacity is a symbolic expression.
            # Check if it's collapsible
            good = True
            try:
                vals = emulator.eval_atmost(capacity, 1)
            except exceptions.UnsatError:
                log.error("Capacity is unsat")
                good = False
            except exceptions.SymbolicValueError:
                log.error("Capacity did not collapse to one value")
                good = False

            if not good or len(vals) > 1:
                log.error("The following fields are lengths:")
                for var in capacity.variables:
                    log.error(f"   {var}")
                log.error("Concretize them to continue analysis")
                raise PathTerminationSignal()

            length = vals[0]
        else:
            length = capacity.concrete_value

        heap_end = int.from_bytes(
            emulator.read_memory_content(self.heap_addr, 8), "little"
        )
        heap_ptr = int.from_bytes(
            emulator.read_memory_content(self.heap_addr + 8, 8), "little"
        )

        if heap_end - heap_ptr < length:
            # OOM; Return NULL
            log.warning(
                f"malloc: OOM! Need {length}, only have {hex(heap_end)} - {hex(heap_ptr)} = {heap_end - heap_ptr}"
            )
            res = 0
        else:
            # Return the pointer to the new region.
            log.warning(f"malloc: Alloc'd {length} bytes at {hex(heap_ptr)}")
            res = heap_ptr
            heap_ptr += length
            emulator.write_memory_content(
                self.heap_addr + 8, heap_ptr.to_bytes(8, "little")
            )

            # Check if this is something we want to track.
            fields = list(map(lambda x: x.split("_")[0], capacity.variables))

            if len(fields) != 1:
                # Don't track; too complex
                log.warn("  Length has multiple variables; not solving")
            elif fields[0] not in self.struct_lengths:
                # Don't track; not something we asked to track
                log.warn(f"  Length field {fields[0]} not known")
            else:
                struct_length = self.struct_lengths[fields[0]]
                struct_prefix = self.struct_prefixes[fields[0]]
                struct_labels = self.struct_fields[fields[0]]

                sym = list(filter(lambda x: x.op == "BVS", capacity.leaf_asts()))[0]
                if not isinstance(sym, claripy.ast.bv.BV):
                    raise TypeError("BVS isn't a bitvector: {sym}")
                n = emulator.eval_atmost(sym, 1)[0]

                if length // n != struct_length:
                    # Don't track; not an obvious "n * sizeof(struct foo)"
                    log.warn(f"  {length} // {n} != {struct_length}")
                elif length % struct_length != 0:
                    # Don't track; not an obvious "n * sizeof(struct foo)"
                    log.warn(f"  {length} not evenly divisible by {n}")
                else:
                    # Track!
                    log.warn(f"  Alloc of {n} items")
                    addr = res
                    for i in range(0, n):
                        struct_fields = list()
                        off = 0
                        for flen, fname in struct_labels:
                            # Build a symbol for this field of this item
                            flabel = struct_prefix + "." + str(i) + "." + fname
                            expr = claripy.BVS(flabel, flen * 8, explicit_name=True)
                            struct_fields.append(expr)

                            # Track the new field
                            r = range(addr + off, addr + off + flen)
                            fda.fda_labels.add(flabel)
                            fda.fda_addr_to_label[r] = flabel
                            fda.fda_label_to_addr[flabel] = r
                            fda.fda_bindings[flabel] = expr

                            off += flen

                        # Insert the whole struct into memory
                        expr = claripy.Concat(*struct_fields)
                        emulator.write_memory(addr, expr)

                        addr += struct_length

                    # Hook the entire array
                    fda.fda_mem_ranges.add((res, res + length))
                    emulator.hook_memory_read_symbolic(
                        res, res + length, self.read_callback
                    )
                    emulator.hook_memory_write_symbolic(
                        res, res + length, self.write_callback
                    )

        emulator.write_register_content(self.ret_reg, res)


class FreeModel(state.models.Model):
    name = "free"
    platform = platforms.Platform(
        platforms.Architecture.X86_64, platforms.Byteorder.LITTLE
    )
    abi = platforms.ABI.SYSTEMV

    def __init__(self, address: int):
        super().__init__(address)

    def model(self, emulator: emulators.Emulator):
        # Just free it.
        return
