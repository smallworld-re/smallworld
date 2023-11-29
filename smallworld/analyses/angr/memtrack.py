from angr.storage.memory_mixins import MemoryMixin


class TrackerMemoryMixin(MemoryMixin):
    """
    Memory mixin for tracking used data.

    Printing every AMD64 register is a pain,
    and finding used memory in angr is a pain.
    This tracks which parts of memory are in use,
    mostly to avoid overprinting.
    """

    # NOTE: This class needs to go in a pretty specific place in a mixin hierarchy.
    #
    # It needs to go above anything that overrides _default_value(),
    # or else it will pick up defaulting addresses before they are defined,
    # possibly resulting in recursive calls if you try to use pp().
    #
    # Conversely, it should go below anything that alters
    # what is actually getting passed to the default memory mixins,
    # such as the divergence plugin.
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.dirty = dict()
        self.dirty_addrs = set()

    @MemoryMixin.memo
    def copy(self, memo):
        o = super().copy(memo)
        o.dirty = dict()
        o.dirty.update(self.dirty)
        o.dirty_addrs = set()
        o.dirty_addrs.update(self.dirty_addrs)
        return o

    def _track_memory(self, addr, size):
        """
        Mark a memory range as 'in-use'
        """
        # TODO: Make this more efficient
        # Detecting overlapping ranges is a pain.
        # This implementation is easy, but its memory usage
        # and runtime cost will explode violently
        # if large amounts of memory are in use.
        track = False
        for i in range(0, size):
            if not track and addr + i not in self.dirty_addrs:
                track = True
                self.dirty[addr] = size
            self.dirty_addrs.add(addr + i)
        if track:
            self.log.debug(f"Tracking {addr:x}, {size}")

    def _default_value(self, addr, size, **kwargs):
        out = super()._default_value(addr, size, **kwargs)
        self._track_memory(addr, size)
        return out

    def _store_one_addr(
        self, concrete_addr, data, trivial, addr, condition, size, **kwargs
    ):
        out = super()._store_one_addr(
            concrete_addr, data, trivial, addr, condition, size, **kwargs
        )
        self._track_memory(concrete_addr, size)
        return out

    def pp(self, log):
        addrs = list(self.dirty.keys())
        addrs.sort()
        for addr in addrs:
            size = self.dirty[addr]
            if self.id == "reg":
                name = self.state.arch.register_size_names[(addr, size)]
            else:
                name = f"0x{addr:x}"
            val = self.load(addr, size, disable_actions=True)
            log(f"\t{name}: {val}")
