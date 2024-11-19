import copy
import logging

import angr

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
        self.heap = copy.deepcopy(heap)
        self.nonce = 0

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

        value = smallworld.state.EmptyValue(length, None, f"malloc_buf_{self.nonce}")
        self.nonce += 1
        self.heap.allocate(value)

        raise Exception("MALLOC!")


class FreeModel(smallworld.state.models.Model):
    name = "free"
    platform = smallworld.platforms.Platform(
        smallworld.platforms.Architecture.X86_64, smallworld.platforms.Byteorder.LITTLE
    )
    abi = smallworld.platforms.ABI.SYSTEMV

    def __init__(self, address: int, malloc: MallocModel):
        super().__init__(address)
        self.heap = malloc.heap

    def model(self, emulator: smallworld.emulators.Emulator):
        raise Exception("FREE!")
