import angr

from .fixups import FixupMemoryMixin
from .memtrack import TrackerMemoryMixin


class DefaultMemoryPlugin(  # type: ignore[misc]
    TrackerMemoryMixin, FixupMemoryMixin, angr.storage.DefaultMemory
):
    pass
