from angr.storage.memory_mixins.memory_mixin import MemoryMixin


class BaseMemoryMixin(MemoryMixin):  # type: ignore[misc]
    """Base class for memory mixins.

    I wanted to add the _setup_tui() method,
    and needed a base class to make multiple inheritance happen cleanly.
    """

    def _setup_tui(self):
        pass
