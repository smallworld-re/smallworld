from ... import platforms
from .typing import AbstractGhidraEmulator


def GhidraEmulator(platform: platforms.Platform) -> AbstractGhidraEmulator:
    """Factory for creating a GhidraEmulator

    Importing any of the pyghidra packages requires
    booting up a JVM, which takes several seconds.
    It also doesn't work if Java and Ghidra are not configured.

    Rather than requiring all SmallWorld users to sit through
    this process, export a factory method that looks
    exactly like an Emulator constructor.
    Only boot pyghidra if the factory is called,
    and only import GhidraEmulator if successful.

    See GhidraEmulator in pcode.py for the actua emulator class.

    Arguments:
        platform: The platform to use when creating the emulator

    Returns:
        A GhidraEmulator object
    """

    import pyghidra

    if not pyghidra.started():
        pyghidra.start()

    from .ghidra import GhidraEmulator as Emu

    return Emu(platform)


__all__ = ["GhidraEmulator"]
