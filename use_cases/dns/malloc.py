import logging
import typing

import angr
import claripy

import smallworld
from smallworld.emulators.angr.exceptions import PathTerminationSignal

log = logging.getLogger(__name__)


class MallocModel(smallworld.state.models.Model):
    name = "malloc"
    platform = smallworld.platforms.Platform(
        smallworld.platforms.Architecture.X86_64, smallworld.platforms.Byteorder.LITTLE
    )
    abi = smallworld.platforms.ABI.SYSTEMV

    def __init__(
        self,
        address: int,
        heap: smallworld.state.memory.heap.Heap,
        read_callback,
        write_callback,
    ):
        super().__init__(address)
        self.nonce = 0
        if len(heap) > 0:
            raise smallworld.exceptions.ConfigurationError(
                "This only works with a blank heap"
            )
        end = smallworld.state.IntegerValue(heap.address + heap.get_capacity(), 8, None)
        ptr = smallworld.state.IntegerValue(heap.address + 16, 8, None)

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

    def model(self, emulator: smallworld.emulators.Emulator):
        if not isinstance(emulator, smallworld.emulators.AngrEmulator):
            raise smallworld.exceptions.ConfigurationError("Model only works with angr")
        # Read the capacity.
        # Bypass the smallworld API; I want to know if it's symbolic
        capacity = emulator.state.regs.rdi
        length = 0

        if capacity.symbolic:
            # Capacity is a symbolic expression.
            # Check if it's collapsible
            good = True
            try:
                vals = emulator.state.solver.eval_atmost(capacity, 1)
            except angr.errors.SimUnsatError:
                log.error("Capacity is unsat")
                good = False
            except angr.errors.SimValueError:
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
                n = emulator.state.solver.eval_atmost(sym, 1)[0]

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
                            emulator.state.scratch.fda_labels.add(flabel)
                            emulator.state.scratch.fda_addr_to_label[r] = flabel
                            emulator.state.scratch.fda_label_to_addr[flabel] = r
                            emulator.state.scratch.fda_bindings[flabel] = expr

                            off += flen

                        # Insert the whole struct into memory
                        expr = claripy.Concat(*struct_fields)
                        emulator.state.memory.store(addr, expr, inspect=False)

                        addr += struct_length

                    # Hook the entire array
                    emulator.state.scratch.fda_mem_ranges.add((res, res + length))
                    emulator.hook_memory_read(res, res + length, self.read_callback)
                    emulator.hook_memory_write(res, res + length, self.write_callback)

        emulator.write_register_content("rax", res)


class FreeModel(smallworld.state.models.Model):
    name = "free"
    platform = smallworld.platforms.Platform(
        smallworld.platforms.Architecture.X86_64, smallworld.platforms.Byteorder.LITTLE
    )
    abi = smallworld.platforms.ABI.SYSTEMV

    def __init__(self, address: int):
        super().__init__(address)

    def model(self, emulator: smallworld.emulators.Emulator):
        # Just free it.
        return
