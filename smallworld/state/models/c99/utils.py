from .... import emulators

# Maximum string length.
# Used to terminate unbounded string operations
MAX_STRLEN = 0x10000

# Common memory manipulation operations used by a lot of library functions.


def _readable_extent(emulator: emulators.Emulator, addr: int, limit: int) -> int:
    """Number of contiguous mapped bytes available at ``addr``, capped at ``limit``.

    Returns ``limit`` unchanged when the emulator exposes no memory map (the
    default base implementation returns ``[]``) or when ``addr`` is not covered,
    so callers preserve their original read-and-maybe-fault behavior in those
    cases. Used to keep speculative bulk reads from running off the end of a
    mapped region.
    """
    mapped = emulator.get_memory_map()
    if not mapped:
        return limit
    for start, stop in mapped:
        if start <= addr < stop:
            return min(stop, addr + limit) - addr
    return limit


def _emu_strnlen(emulator: emulators.Emulator, addr: int, n: int) -> int:
    sl = 0
    while sl < n:
        # read_memory returns the bytes or raises on fault; it never returns None.
        b = emulator.read_memory(addr + sl, 1)[0]
        if b == 0:
            break
        sl += 1
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
    def _byte_scan() -> int:
        for i in range(0, n):
            char1 = emulator.read_memory(ptr1 + i, 1)[0]
            char2 = emulator.read_memory(ptr2 + i, 1)[0]
            if char1 != char2:
                return char1 - char2
        return 0

    # Fast path: read both regions in one round-trip each and compare in
    # Python. Clamp the bulk read to what's actually mapped so an operand near
    # a segment boundary doesn't trigger a wasted over-read that always faults.
    # If a clamped read still faults (a symbolic byte within the mapped extent),
    # fall back to the byte-at-a-time scan so we stop at exactly the same byte
    # the original loop did.
    avail = min(
        _readable_extent(emulator, ptr1, n),
        _readable_extent(emulator, ptr2, n),
    )
    try:
        b1 = emulator.read_memory(ptr1, avail)
        b2 = emulator.read_memory(ptr2, avail)
    except Exception:
        return _byte_scan()
    for i in range(0, avail):
        if b1[i] != b2[i]:
            return b1[i] - b2[i]
    if avail < n:
        # Undecided within the mapped extent; the remaining bytes are unmapped
        # for at least one operand, so scan byte-at-a-time to fault exactly
        # where the original loop would.
        return _byte_scan()
    return 0


def _emu_strncmp(emulator: emulators.Emulator, ptr1: int, ptr2: int, n: int) -> int:
    def _byte_scan() -> int:
        for i in range(0, n):
            char1 = emulator.read_memory(ptr1 + i, 1)[0]
            char2 = emulator.read_memory(ptr2 + i, 1)[0]
            if char1 == 0 or char2 == 0 or char1 != char2:
                return char1 - char2
        return 0

    # Fast path: bulk-read both strings and scan in Python, stopping at the
    # first NUL or mismatch. Clamp the bulk read to what's actually mapped so a
    # string near a segment boundary doesn't trigger a wasted MAX_STRLEN
    # over-read that always faults (strcmp calls this with n == MAX_STRLEN). If
    # a clamped read still faults (a symbolic byte within the mapped extent),
    # fall back to the byte-at-a-time scan so behavior is identical.
    avail = min(
        _readable_extent(emulator, ptr1, n),
        _readable_extent(emulator, ptr2, n),
    )
    try:
        b1 = emulator.read_memory(ptr1, avail)
        b2 = emulator.read_memory(ptr2, avail)
    except Exception:
        return _byte_scan()
    for i in range(0, avail):
        char1 = b1[i]
        char2 = b2[i]
        if char1 == 0 or char2 == 0 or char1 != char2:
            return char1 - char2
    if avail < n:
        # No NUL or mismatch within the mapped extent; the remaining bytes are
        # unmapped for at least one operand, so scan byte-at-a-time to fault
        # exactly where the original loop would.
        return _byte_scan()
    return 0


def _emu_strncat(emulator: emulators.Emulator, dst: int, src: int, n: int) -> None:
    if n == 0:
        return
    # read_memory raises on unmapped/symbolic memory (it never returns None),
    # so unavailable operands surface as an exception here rather than a silent
    # skip -- consistent with every other helper in this module.
    ld = _emu_strnlen(emulator, dst, MAX_STRLEN)
    ls = _emu_strnlen(emulator, src, MAX_STRLEN)
    lsn = min(ls, n)
    src_bytes = emulator.read_memory(src, lsn) + b"\0"
    emulator.write_memory(dst + ld, src_bytes)
