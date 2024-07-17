import angr

from .memtrack import TrackerMemoryMixin


class DefaultMemoryPlugin(TrackerMemoryMixin, angr.storage.DefaultMemory):
    pass
