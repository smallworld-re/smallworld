try:
    import pyghidra

    if not pyghidra.started():
        pyghidra.start()
    from .pcode import GhidraEmulator

    __all__ = ["GhidraEmulator"]
except ValueError:
    # Ghidra not configured; live with it.
    pass
except Exception as e:
    raise e
