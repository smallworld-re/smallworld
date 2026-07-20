import logging
import typing

from ... import emulators, exceptions
from .mmio import MemoryMappedModel

logger = logging.getLogger(__name__)


def _overlap(
    model: MemoryMappedModel, addr: int, size: int
) -> typing.Optional[typing.Tuple[int, int, int]]:
    """Intersect an access with the modeled region.

    Returns ``(access_offset, region_offset, length)`` where ``access_offset``
    is the offset into the access, ``region_offset`` the offset into the
    region, and ``length`` the number of overlapping bytes -- or ``None`` if
    the access does not overlap the region at all.
    """
    start = max(addr, model.address)
    end = min(addr + size, model.address + model.size)
    if start >= end:
        return None
    return (start - addr, start - model.address, end - start)


class NullMemoryMappedModel(MemoryMappedModel):
    """A default MMIO model that does nothing.

    Reads within the region report zeroes and writes to it have no visible
    effect.  Useful for mapping a device region inert -- e.g. to stop a
    driver faulting on an unmodeled peripheral without caring what it reads
    back.

    Arguments:
        address: Starting address of the MMIO region.
        size: Size of the MMIO region in bytes.
    """

    def on_read(
        self, emu: emulators.Emulator, addr: int, size: int, data: bytes
    ) -> typing.Optional[bytes]:
        # An access may overlap our region only partially (it can start
        # before or extend past the region), and the emulator writes the
        # whole returned buffer back -- so zero only the overlapping bytes
        # and pass the rest of `data` through untouched.
        overlap = _overlap(self, addr, size)
        if overlap is None:
            return None
        acc_off, _, length = overlap
        result = bytearray(data)
        result[acc_off : acc_off + length] = b"\x00" * length
        return bytes(result)

    def on_write(
        self, emu: emulators.Emulator, addr: int, size: int, value: bytes
    ) -> None:
        # Nothing to do.  Write hooks are observational (no return channel);
        # the emulator still stores the bytes to real memory itself.  We
        # simply never surface them, since on_read always reports zeroes.
        pass


class RAMMemoryMappedModel(MemoryMappedModel):
    """A default MMIO model that behaves like plain memory.

    Bytes written are stored in the model object and returned by a
    corresponding read, so the region acts like ordinary RAM while still
    routing through the MMIO hooks (e.g. so a harness can inspect what a
    program wrote).  The backing bytes are exposed as ``self.data`` and
    start out zeroed.

    Arguments:
        address: Starting address of the MMIO region.
        size: Size of the MMIO region in bytes.
    """

    def __init__(self, address: int, size: int):
        super().__init__(address, size)
        self.data = bytearray(size)

    def on_read(
        self, emu: emulators.Emulator, addr: int, size: int, data: bytes
    ) -> typing.Optional[bytes]:
        # Substitute our stored bytes only for the portion of the access
        # that falls within the region; leave any straddling bytes as read.
        overlap = _overlap(self, addr, size)
        if overlap is None:
            return None
        acc_off, reg_off, length = overlap
        result = bytearray(data)
        result[acc_off : acc_off + length] = self.data[reg_off : reg_off + length]
        return bytes(result)

    def on_write(
        self, emu: emulators.Emulator, addr: int, size: int, value: bytes
    ) -> None:
        # Record only the portion of the write that lands in the region.
        # Bytes outside the region are stored to real memory by the emulator
        # itself; write hooks have no return channel, so out-of-region bytes
        # are neither our concern nor something we could forward.
        overlap = _overlap(self, addr, size)
        if overlap is None:
            return
        acc_off, reg_off, length = overlap
        self.data[reg_off : reg_off + length] = value[acc_off : acc_off + length]


class UnmappedMemoryMappedModel(MemoryMappedModel):
    """A default MMIO model that faults on any access.

    Any read raises ``EmulationReadUnmappedFailure`` and any write raises
    ``EmulationWriteUnmappedFailure``, as though the region were not mapped.
    Useful as the slack for :class:`SparseMemoryMappedModel`, so that
    accesses to the gaps between registers fault like unmapped memory
    instead of silently succeeding.

    Arguments:
        address: Starting address of the MMIO region.
        size: Size of the MMIO region in bytes.
    """

    def on_read(
        self, emu: emulators.Emulator, addr: int, size: int, data: bytes
    ) -> typing.Optional[bytes]:
        raise exceptions.EmulationReadUnmappedFailure(
            f"read from unmapped MMIO region at {addr:#x}",
            emu.read_register("pc"),
            address=addr,
        )

    def on_write(
        self, emu: emulators.Emulator, addr: int, size: int, value: bytes
    ) -> None:
        raise exceptions.EmulationWriteUnmappedFailure(
            f"write to unmapped MMIO region at {addr:#x}",
            emu.read_register("pc"),
            address=addr,
        )


class SparseMemoryMappedModel(MemoryMappedModel):
    """A default MMIO model for a large, sparsely-populated region.

    A single model owns the whole region -- the emulator only allows one
    hook per address range, so a big region with scattered registers must be
    served by one model that dispatches internally.  Register handlers for
    individual sub-regions with :meth:`add_register`; everything not covered
    by a registered handler is served by a "slack" model (zeroed by default,
    or RAM-backed).

    Handlers only ever see accesses fully contained within their own
    sub-region.  This model splits each access at sub-region boundaries and
    routes the pieces, so authors never have to deal with partial or
    straddling accesses themselves.

    Arguments:
        address: Starting address of the region.
        size: Size of the region in bytes.
        slack: Behavior for bytes not covered by a registered handler.
            ``"null"`` (default) reports zeroes and discards writes; ``"ram"``
            stores writes and reads them back; ``"unmapped"`` faults on any
            access.  A ``MemoryMappedModel`` instance spanning the whole
            region may be passed for custom behavior.
    """

    def __init__(
        self,
        address: int,
        size: int,
        slack: typing.Union[str, MemoryMappedModel] = "null",
    ):
        super().__init__(address, size)
        if isinstance(slack, MemoryMappedModel):
            if slack.address != address or slack.size != size:
                raise ValueError("slack model must span the whole region")
            self.slack: MemoryMappedModel = slack
        elif slack == "null":
            self.slack = NullMemoryMappedModel(address, size)
        elif slack == "ram":
            self.slack = RAMMemoryMappedModel(address, size)
        elif slack == "unmapped":
            self.slack = UnmappedMemoryMappedModel(address, size)
        else:
            raise ValueError(f"unknown slack policy {slack!r}")
        # Kept sorted by address; guaranteed non-overlapping by add_register.
        self._children: typing.List[MemoryMappedModel] = []

    def add_register(self, child: MemoryMappedModel) -> MemoryMappedModel:
        """Register a handler for a sub-region.

        ``child`` is any ``MemoryMappedModel`` whose own ``address``/``size``
        place it within this region.  Returns ``child`` for convenience.

        Raises:
            ValueError: If the child does not fit within the region, or
                overlaps an already-registered child.
        """
        if (
            child.address < self.address
            or child.address + child.size > self.address + self.size
        ):
            raise ValueError(
                f"register [{child.address:#x}, {child.address + child.size:#x}) "
                f"does not fit within region "
                f"[{self.address:#x}, {self.address + self.size:#x})"
            )
        for existing in self._children:
            if (
                child.address < existing.address + existing.size
                and existing.address < child.address + child.size
            ):
                raise ValueError(
                    f"register [{child.address:#x}, "
                    f"{child.address + child.size:#x}) overlaps "
                    f"[{existing.address:#x}, {existing.address + existing.size:#x})"
                )
        self._children.append(child)
        self._children.sort(key=lambda c: c.address)
        return child

    def _runs(
        self, start: int, end: int
    ) -> typing.Iterator[typing.Tuple[int, int, MemoryMappedModel]]:
        """Split ``[start, end)`` into maximal runs, each owned by one model.

        Yields ``(run_start, run_end, owner)`` where ``owner`` is the child
        covering the run, or the slack model for a gap between children.
        """
        pos = start
        while pos < end:
            owner: typing.Optional[MemoryMappedModel] = None
            run_end = end
            for c in self._children:
                if c.address <= pos < c.address + c.size:
                    # `pos` is inside this child; the run lasts to its end.
                    owner = c
                    run_end = min(end, c.address + c.size)
                    break
                if c.address > pos:
                    # Children are sorted, so this is the next one; the run of
                    # slack lasts until it begins.
                    run_end = min(end, c.address)
                    break
            if owner is None:
                owner = self.slack
            yield pos, run_end, owner
            pos = run_end

    def on_read(
        self, emu: emulators.Emulator, addr: int, size: int, data: bytes
    ) -> typing.Optional[bytes]:
        if _overlap(self, addr, size) is None:
            return None
        result = bytearray(data)
        c_start = max(addr, self.address)
        c_end = min(addr + size, self.address + self.size)
        for run_start, run_end, owner in self._runs(c_start, c_end):
            lo = run_start - addr
            hi = run_end - addr
            # Each owner sees only its own contained sub-access.
            sub = owner.on_read(
                emu, run_start, run_end - run_start, bytes(result[lo:hi])
            )
            if sub is not None:
                result[lo:hi] = sub
        return bytes(result)

    def on_write(
        self, emu: emulators.Emulator, addr: int, size: int, value: bytes
    ) -> None:
        if _overlap(self, addr, size) is None:
            return
        c_start = max(addr, self.address)
        c_end = min(addr + size, self.address + self.size)
        for run_start, run_end, owner in self._runs(c_start, c_end):
            lo = run_start - addr
            hi = run_end - addr
            owner.on_write(emu, run_start, run_end - run_start, value[lo:hi])


__all__ = [
    "NullMemoryMappedModel",
    "RAMMemoryMappedModel",
    "UnmappedMemoryMappedModel",
    "SparseMemoryMappedModel",
]
