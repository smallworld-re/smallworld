from ... import platforms
from .typing import AbstractGhidraEmulator, AbstractGhidraSymbolicEmulator


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


def GhidraSymbolicEmulator(
    platform: platforms.Platform,
    taint: bool = False,
    taint_addresses: bool = False,
) -> AbstractGhidraSymbolicEmulator:
    """Factory for creating a :class:`GhidraSymbolicEmulator`.

    Same lazy-boot pattern as :func:`GhidraEmulator`, but additionally
    extracts and loads Ghidra's ``SymbolicSummaryZ3`` extension (jars + native
    libz3) into the JVM before the symbolic module is imported.

    Arguments:
        platform: The platform to use when creating the emulator.
        taint: Enable dynamic taint tracking (disabled by default).
        taint_addresses: Also propagate taint through addresses.

    Returns:
        A :class:`GhidraSymbolicEmulator` instance.
    """

    from . import symz3_loader

    symz3_loader.ensure_loaded()

    from .symbolic import GhidraSymbolicEmulator as Emu

    return Emu(platform, taint=taint, taint_addresses=taint_addresses)


__all__ = ["GhidraEmulator", "GhidraSymbolicEmulator"]
