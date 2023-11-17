from angr.storage.memory_mixins import MemoryMixin


class SWBaseMemoryMixin(MemoryMixin):
    """
    Base class for SmallWorld memory mixins.

    I wanted to add the _setup_tui() method,
    and needed a base class to make multiple inheritance happen cleanly.
    """

    def _setup_tui(self):
        pass
