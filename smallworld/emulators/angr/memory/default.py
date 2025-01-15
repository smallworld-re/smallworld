import angr

from .memtrack import TrackerMemoryMixin


class DefaultMemoryPlugin(
    TrackerMemoryMixin, angr.storage.DefaultMemory
):  # type: ignore[misc]
    pass
