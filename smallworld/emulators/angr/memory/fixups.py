from angr.storage.memory_mixins.memory_mixin import MemoryMixin


class FixupMemoryMixin(MemoryMixin):
    """Mixin providing some basic bug-fixed/feature improvements

    angr doesn't always behave as I'd expect.
    This mixin helps things a little.
    """

    def _concretize_addr(self, supercall, addr, strategies=None, condition=None):
        # Handle potential errors durring concretization
        # This works the same for reads and writes, so why duplicate code?

        if not self.state.solver.satisfiable():
            # This state isn't satisfiable; concretization is impossible, but irrelevant.
            #
            # Under some conditions of which I'm uncertain,
            # the concretizer will try to run even if the state is already unsat.
            # Since the concretizer relies on the solver,
            # it fails with a big ole' fatal exception.
            #
            # The successor computation will eventually kill these states anyway,
            # so just return a dummy value to keep things running.
            return [0xDEAD0000]

        return supercall(addr, strategies=strategies, condition=condition)

    def concretize_read_addr(self, addr, strategies=None, condition=None):
        return self._concretize_addr(
            super().concretize_read_addr,
            addr,
            strategies=strategies,
            condition=condition,
        )

    def concretize_write_addr(self, addr, strategies=None, condition=None):
        return self._concretize_addr(
            super().concretize_write_addr,
            addr,
            strategies=strategies,
            condition=condition,
        )
