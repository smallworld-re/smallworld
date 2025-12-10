import logging

from .... import emulators

logger = logging.getLogger(__name__)

# Maximum string length.
# Used to terminate unbounded string operations
MAX_STRLEN = 0x10000

# Common memory manipulation operations used by a lot of library functions.


def _emu_strnlen(emulator: emulators.Emulator, addr: int, n: int) -> int:
    sl = 0
    while sl <= n:
        b_opt = emulator.read_memory(addr + sl, 1)
        if b_opt is not None:
            b = b_opt[0]
            if b == 0:
                break
            sl += 1
        else:
            assert b_opt is not None
    return sl


def _emu_strlen(emulator: emulators.Emulator, addr: int) -> int:
    return _emu_strnlen(emulator, addr, MAX_STRLEN)


def _emu_memcpy(emulator: emulators.Emulator, dst: int, src: int, n: int) -> None:
    src_bytes = emulator.read_memory(src, n)
    emulator.write_memory(dst, src_bytes)


def _emu_strncpy(emulator: emulators.Emulator, dst: int, src: int, n: int) -> None:
    # strncpy is slightly different from strcpy and memcpy;
    # it zero-fills any unused space in the buffer.
    actual = n
    src_len = _emu_strlen(emulator, src) + 1
    if src_len < n:
        actual = src_len

    data = emulator.read_memory(src, actual)
    data += b"\0" * (n - actual)

    emulator.write_memory(dst, data)


def _emu_memcmp(emulator: emulators.Emulator, ptr1: int, ptr2: int, n: int) -> int:
    for i in range(0, n):
        char1 = emulator.read_memory(ptr1 + i, 1)[0]
        char2 = emulator.read_memory(ptr2 + i, 1)[0]
        if char1 != char2:
            return char1 - char2
    return 0


def _emu_strncmp(emulator: emulators.Emulator, ptr1: int, ptr2: int, n: int) -> int:
    for i in range(0, n):
        char1 = emulator.read_memory(ptr1 + i, 1)[0]
        char2 = emulator.read_memory(ptr2 + i, 1)[0]
        if char1 == 0 or char2 == 0:
            return char1 - char2
        elif char1 != char2:
            return char1 - char2
    return 0


def _emu_strncat(emulator: emulators.Emulator, dst: int, src: int, n: int) -> None:
    if n == 0:
        return
    if emulator.read_memory(src, 1) is None:
        logger.debug("MEM not available in strncpy read @ {src:x}")
    elif emulator.read_memory(dst, 1) is None:
        logger.debug("MEM not available in strncpy write @ {dst:x}")
    else:
        # at least a byte is available at both src and dst
        ld = _emu_strnlen(emulator, dst, MAX_STRLEN)
        ls = _emu_strnlen(emulator, src, MAX_STRLEN)
        lsn = min(ls, n)
        b_opt = emulator.read_memory(src, lsn)
        if b_opt is not None:
            src_bytes = b_opt + b"\0"
            emulator.write_memory(dst + ld, src_bytes)
        else:
            assert b_opt is not None
