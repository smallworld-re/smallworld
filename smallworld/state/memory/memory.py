import os
import typing

import claripy

from ... import emulators, exceptions, platforms
from .. import state


class Memory(state.Stateful, dict[int, state.Value]):
    """A memory region.

    A memory maps integer offsets (implicitly from the base ``address``)
    to ``Value`` objects.
    """

    def __init__(
        self,
        address: int,
        size: int,
        *args,
        **kwargs,
    ) -> None:
        super().__init__(*args, **kwargs)

        self.address: int = address
        """The start address of this memory region."""

        self.size: int = size
        """The size address of this memory region."""

    def to_bytes(self) -> bytes:
        """Convert this memory region into a byte string.

        Missing/undefined space will be filled with zeros.

        Arguments:
            byteorder: Byteorder for conversion to raw bytes.

        Returns:
            Bytes for this object with the given byteorder.
        """

        result = b"\x00" * self.size
        for offset, value in self.items():
            # data = value.get_content()
            result = (
                result[:offset] + value.to_bytes() + result[offset + value.get_size() :]
            )

        return result

    def get_capacity(self) -> int:
        """Gets the total number of bytes this memory region can store.
        Returns:
                    The total number of bytes this memory region can store.
        """
        return self.size

    def get_used(self) -> int:
        """Gets the number of bytes written to this memory region.

        Returns:
            The number of bytes written to this memory region.
        """
        return sum([v.get_size() for v in self.values()])

    def get_size(self) -> int:
        raise NotImplementedError("You probably want get_capacity()")

    def _is_safe(self, value: state.Value):
        if (self.get_used() + value.get_size()) > self.get_capacity():
            raise ValueError("Memory is full")

    def _write_content(
        self, emulator: emulators.Emulator, address: int, value: state.Value
    ):
        # Internal stub; makes it easy for Code to switch to write_code()
        content = value.get_content()
        if isinstance(content, claripy.ast.bv.BV):
            try:
                emulator.write_memory_content(address, content)
                return
            except exceptions.SymbolicValueError:
                pass
        emulator.write_memory_content(address, value.to_bytes())

    def apply(self, emulator: emulators.Emulator) -> None:
        emulator.map_memory(self.address, self.get_capacity())
        for offset, value in self.items():
            if value.get_content() is not None:
                self._write_content(emulator, self.address + offset, value)
            if value.get_type() is not None:
                emulator.write_memory_type(
                    self.address + offset, value.get_size(), value.get_type()
                )
            if value.get_label() is not None:
                emulator.write_memory_label(
                    self.address + offset, value.get_size(), value.get_label()
                )

    def extract(self, emulator: emulators.Emulator) -> None:
        value: state.Value
        try:
            bytes = emulator.read_memory(self.address, self.get_capacity())
            value = state.BytesValue(bytes, f"Extracted memory from {self.address}")
        except exceptions.SymbolicValueError:
            expr = emulator.read_memory_symbolic(self.address, self.get_capacity())
            value = state.SymbolicValue(
                self.get_capacity(), expr, None, f"Extracted memory from {self.address}"
            )
        except Exception as e:
            raise exceptions.EmulationError(
                f"Failed reading {hex(self.address)}"
            ) from e
        self.clear()
        self[0] = value

    def write_bytes(self, address: int, data: bytes) -> None:
        """Overwrite part of this memory region with specific bytes.
        This will fail if any sub-region of the existing memory is symbolic.

        Arguments:
            address: The address to write to.
            data: The bytes to write.
        """

        data_start = address
        data_end = address + len(data)

        if (data_start < self.address) or (data_end > self.address + self.size):
            raise exceptions.ConfigurationError(
                f"Out of bounds: tried to read {len(data)} bytes at {hex(address)} from memory region {hex(self.address)} - {hex(self.address + self.size)}."
            )

        if len(self) == 0:
            # No existing data.
            value = state.BytesValue(data, None)
            self[address - self.address] = value

        segment: state.Value
        gap_start = 0
        for segment_offset, segment in sorted(self.items()):
            segment_start = self.address + segment_offset
            segment_end = segment_start + segment.get_size()

            gap_end = segment_start

            if data_start <= gap_end and gap_start <= data_end:
                # Part of data possibly falls into the gap between segments.
                part_start = max(data_start, gap_start)
                part_end = min(data_end, gap_end)

                part = data[part_start - data_start : part_end - data_start]
                if len(part) > 0:
                    value = state.BytesValue(part, None)
                    self[part_start - self.address] = value

            gap_start = segment_end

            if segment_start >= data_end:
                # This segment is after the range we want to update.
                # I.e. we have completed the write.
                break

            if data_start < segment_end and segment_start < data_end:
                # Part of data lands in this segment
                part_start = max(data_start, segment_start)
                part_end = min(data_end, segment_end)

                part = data[part_start - data_start : part_end - data_start]

                if isinstance(segment, state.SymbolicValue):
                    raise exceptions.SymbolicValueError(
                        f"Tried to write {len(data)} bytes at {hex(address)}.  Data at {hex(segment_start)} - {hex(segment_end)} is symbolic."
                    )

                contents = segment.to_bytes()
                prefix = contents[: part_start - segment_start]
                suffix = contents[part_end - segment_start :]
                new_segment_bytes = prefix + part + suffix

                # set content
                match segment:
                    case state.BytesValue():
                        segment.set_content(new_segment_bytes)
                    case state.IntegerValue():
                        as_int = int.from_bytes(
                            new_segment_bytes, segment.byteorder.value
                        )
                        segment.set_content(as_int)
                    case _:
                        # CTypeValue
                        ctype_subclass = typing.cast(
                            state.CTypesAny, segment.get_type()
                        )
                        as_ctype = ctype_subclass.from_buffer_copy(new_segment_bytes)
                        segment.set_content(as_ctype)

        gap_end = self.address + self.size
        if data_start <= gap_end and gap_start <= data_end:
            # Part of the data goes past the last segment.
            part_start = max(data_start, gap_start)
            part_end = min(data_end, gap_end)

            part = data[part_start - data_start : part_end - data_start]

            if len(part) > 0:
                value = state.BytesValue(part, None)
                self[part_start - self.address] = value

    def read_bytes(self, address: int, size: int) -> bytes:
        """Read part of this memory region.
        This will fail if any sub-region of the memory requested is symbolic or uninitialized.

        Arguments:
            address: The address to read from.
            size: The number of bytes to read.

        Returns:
            The bytes in the requested memory region.
        """

        if (address < self.address) or (address + size > self.address + self.size):
            raise exceptions.ConfigurationError(
                f"Out of bounds: tried to read {size} bytes at {hex(address)} from memory region {hex(self.address)} - {hex(self.address + self.size)}."
            )

        out: bytes = b""
        next_segment_address = address
        remaining_length = size

        segment: state.Value
        for segment_offset, segment in sorted(self.items()):
            # check if segment is in requested range
            segment_address = self.address + segment_offset
            if not (
                segment_address <= next_segment_address
                and next_segment_address < segment_address + segment.get_size()
            ):
                continue

            # check for symbolic value
            if isinstance(segment, state.SymbolicValue):
                raise exceptions.SymbolicValueError(
                    f"Tried to read {size} bytes at {hex(address)}. Data at {hex(segment_address)} - {hex(segment_address + segment.get_size())} is symbolic."
                )

            # find offset of Value in output buffer
            offset_in_segment = next_segment_address - segment_address
            length_in_segment = min(
                remaining_length, segment.get_size() - offset_in_segment
            )

            # append bytes to output buffer
            segment_bytes = segment.to_bytes()
            out += segment_bytes[
                offset_in_segment : offset_in_segment + length_in_segment
            ]
            next_segment_address += length_in_segment
            remaining_length -= length_in_segment

            # check if output complete
            if remaining_length == 0:
                break

        # next segment of requested region not found
        if next_segment_address != address + size:
            raise exceptions.ConfigurationError(
                f"Tried to read {size} bytes at {hex(address)}. Data at {hex(next_segment_address)} is uninitialized."
            )

        return out

    def write_int(
        self,
        address: int,
        value: int,
        size: typing.Literal[1, 2, 4, 8],
        byteorder: platforms.Byteorder,
    ) -> None:
        """Write an integer to memory.
        This will fail if any sub-region of the existing memory is symbolic.

        Arguments:
            address: The address to write to.
            value: The integer value to write.
            size: The size of the integer in bytes.
            endianness: The byteorder of the platform.
        """

        self.write_bytes(
            address, int.to_bytes(value, size, byteorder.value, signed=False)
        )

    def read_int(
        self,
        address: int,
        size: typing.Literal[1, 2, 4, 8],
        byteorder: platforms.Byteorder,
    ) -> int:
        """Read and interpret as an integer.
        This will fail if any sub-region of the memory requested is symbolic or uninitialized.

        Arguments:
            address: The address to read from.
            size: The size of the integer in bytes.
            endianness: The byteorder of the platform.

        Returns:
            The integer read from memory.
        """

        return int.from_bytes(
            self.read_bytes(address, size),
            byteorder.value,
            signed=False,
        )

    def get_ranges_initialized(self) -> list[range]:
        out: list[range] = []

        for segment_offset, segment in sorted(self.items()):
            segment_start = self.address + segment_offset
            segment_end = segment_start + segment.get_size() - 1
            if len(out) > 0 and out[-1].stop + 1 == segment_end:
                segment_start = out.pop().start
            out.append(
                range(
                    segment_start,
                    segment_end,
                )
            )

        return out

    def get_ranges_uninitialized(self) -> list[range]:
        out: list[range] = []
        next_segment_start = self.address

        for segment_offset, segment in sorted(self.items()):
            segment_start = self.address + segment_offset
            segment_end = segment_start + segment.get_size()
            if next_segment_start != segment_start:
                out.append(range(next_segment_start, segment_start - 1))
            next_segment_start = segment_end

        if next_segment_start != self.address + self.get_capacity():
            out.append(
                range(next_segment_start, self.address + self.get_capacity() - 1)
            )

        return out

    def get_ranges_symbolic(self):
        out: list[range] = []

        for segment_offset, segment in sorted(self.items()):
            if not isinstance(segment, state.SymbolicValue):
                continue
            segment_start = self.address + segment_offset
            segment_end = segment_start + segment.get_size() - 1
            if len(out) > 0 and out[-1].stop + 1 == segment_end:
                segment_start = out.pop().start
            out.append(
                range(
                    segment_start,
                    segment_end,
                )
            )

        return out

    def get_ranges_concrete(self):
        out: list[range] = []

        for segment_offset, segment in sorted(self.items()):
            if isinstance(segment, state.SymbolicValue):
                continue
            segment_start = self.address + segment_offset
            segment_end = segment_start + segment.get_size() - 1
            if len(out) > 0 and out[-1].stop + 1 == segment_end:
                segment_start = out.pop().start
            out.append(
                range(
                    segment_start,
                    segment_end,
                )
            )

        return out

    def __hash__(self):
        return super(dict, self).__hash__()


class RawMemory(Memory):
    @classmethod
    def from_bytes(cls, bytes: bytes, address: int):
        """Load from a byte array.

        Arguments:
            bytes: The bytes of the memory.
            address: The address where this memory should be loaded
               into an emulator's memory.

        Returns:
            A RawMemory contstructed from the given bytes.
        """

        memory = cls(address=address, size=len(bytes))
        memory[0] = state.BytesValue(bytes, None)

        return memory

    @classmethod
    def from_file(
        cls, file: typing.BinaryIO, address: int, label: typing.Optional[str] = None
    ):
        """Load from an open file-like object.

        Arguments:
            file: The open file-like object from which to load data.
            address: The address where this memory should be loaded
               into an emulator's memory.

        Returns:
            A RawMemory from the given file-like object.
        """

        data, size = file.read(), file.tell()

        memory = cls(address=address, size=size)
        memory[0] = state.BytesValue(data, label)

        return memory

    @classmethod
    def from_filepath(cls, path: str, address: int):
        """Load from a file.

        Arguments:
            path: The path to the file.
            address: The address where this memory should be loaded
               into an emulator's memory.

        Returns:
            A RawMemory parsed from the given file path.
        """

        path = os.path.abspath(os.path.expanduser(path))

        with open(path, "rb") as f:
            return cls.from_file(file=f, address=address)


__all__ = ["Memory", "RawMemory"]
