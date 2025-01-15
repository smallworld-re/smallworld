import angr

from .memtrack import TrackerMemoryMixin


class DefaultMemoryPlugin(  # type: ignore[misc]
    TrackerMemoryMixin, angr.storage.DefaultMemory
):
    pass
