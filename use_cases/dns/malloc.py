import logging

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

    def __init__(self, address: int, heap: smallworld.state.memory.heap.Heap):
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

    def model(self, emulator: smallworld.emulators.Emulator):
        if not isinstance(emulator, smallworld.emulators.AngrEmulator):
            raise smallworld.exceptions.ConfigurationError("Model only works with angr")
        # Read the capacity.
        # Bypass the smallworld API; I want to know if it's symbolic
        capacity = emulator.state.regs.rdi
        length = 0

        log.warning(f"Requested capacity: {capacity}")

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
        log.warning(f"Collapsed to {length}")

        heap_end = int.from_bytes(
            emulator.read_memory_content(self.heap_addr, 8), "little"
        )
        heap_ptr = int.from_bytes(
            emulator.read_memory_content(self.heap_addr + 8, 8), "little"
        )

        if heap_end - heap_ptr < length:
            # Return NULL
            res = 0
        else:
            log.warning(f"Assigned pointer {hex(heap_ptr)}")
            res = heap_ptr
            heap_ptr += length
            emulator.state.memory.store(self.heap_addr + 8, claripy.BVV(heap_ptr, 64))

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
