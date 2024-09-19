from __future__ import annotations

import abc
import copy
import ctypes
import typing

from .. import emulators, exceptions, platforms, utils


class Stateful(metaclass=abc.ABCMeta):
    """System state that can be applied to/loaded from an emulator."""

    @abc.abstractmethod
    def extract(self, emulator: emulators.Emulator) -> None:
        """Load state from an emulator.

        Arguments:
            emulator: The emulator from which to load
        """

    @abc.abstractmethod
    def apply(self, emulator: emulators.Emulator) -> None:
        """Apply state to an emulator.

        Arguments:
            emulator: The emulator to which state should applied.
        """


class Value(metaclass=abc.ABCMeta):
    """An individual state value."""

    _content: typing.Optional[typing.Any] = None
    _type: typing.Optional[typing.Any] = None
    _label: typing.Optional[str] = None

    @abc.abstractmethod
    def get_size(self) -> int:
        """Get the size of this object.

        Returns:
            The size this object should occupy in memory.
        """

        return 0

    def get_content(self) -> typing.Optional[typing.Any]:
        """Get the content of this object.

        Returns:
            The content of this object.
        """

        return self._content

    def set_content(self, content: typing.Optional[typing.Any]) -> None:
        """Set the content of this object.

        Arguments:
            content: The content value to set.
        """

        self._content = content

    def get_type(self) -> typing.Optional[typing.Any]:
        """Get the type of this object.

        Returns:
            The type of this object.
        """

        return self._type

    def set_type(self, type: typing.Optional[typing.Any]) -> None:
        """Set the type of this object.

        Arguments:
            type: The type value to set.
        """

        self._type = type

    def get_label(self) -> typing.Optional[str]:
        """Get the label of this object.

        Returns:
            The label of this object.
        """

        return self._label

    def set_label(self, label: typing.Optional[str]) -> None:
        """Set the label of this object.

        Arguments:
            type: The label value to set.
        """

        self._label = label

    def get(self) -> typing.Optional[typing.Any]:
        """A helper to get the content of this object.

        Returns:
            The content of this object.
        """

        return self.get_content()

    def set(self, content: typing.Optional[typing.Any]) -> None:
        """A helper to set the content of this object.

        Arguments:
            content: The content value to set.
        """

        self.set_content(content)

    @abc.abstractmethod
    def to_bytes(self, byteorder: platforms.Byteorder) -> bytes:
        """Convert this object into a byte string.

        Arguments:
            byteorder: Byteorder for conversion to raw bytes.

        Returns:
            Bytes for this object with the given byteorder.
        """

        return b""

    @classmethod
    def from_ctypes(cls, value: typing.Any, label: str):
        """Load from an existing ctypes object."""

        raise NotImplementedError("loading from ctypes is not yet implemented")


class Register(Value, Stateful):
    """An individual register.

    Arguments:
        name: The canonical name of the register.
        size: The size (in bytes) of the register.
    """

    _content: typing.Optional[int] = None
    _type = None
    _label = None

    def __init__(self, name: str, size: int = 4):
        super().__init__()

        self.name: str = name
        """Canonical name."""

        self.size = size
        """Register size in bytes."""

    def get_size(self) -> int:
        return self.size

    def extract(self, emulator: emulators.Emulator) -> None:
        self.set_content(emulator.read_register_content(self.name))
        self.set_type(emulator.read_register_type(self.name))
        self.set_label(emulator.read_register_label(self.name))

    def apply(self, emulator: emulators.Emulator) -> None:
        emulator.write_register_content(self.name, self.get_content())
        emulator.write_register_type(self.name, self.get_type())
        emulator.write_register_label(self.name, self.get_label())

    def to_bytes(self, byteorder: platforms.Byteorder) -> bytes:
        value = self.get_content()

        if byteorder == platforms.Byteorder.LITTLE:
            return value.to_bytes(self.size, byteorder="little")
        elif byteorder == platforms.Byteorder.BIG:
            return value.to_bytes(self.size, byteorder="big")
        else:
            raise ValueError(f"unsupported byteorder {byteorder}")


class RegisterAlias(Register):
    """An alias to a partial register.

    Arguments:
        name: The cannonical name of the register.
        reference: A register which this alias references.
        size: The size (in bytes) of the register.
        offset: The offset from the start of the register that this alias
            references.

    """

    def __init__(self, name: str, reference: Register, size: int = 4, offset: int = 0):
        super().__init__(name, size)

        self.reference: Register = reference
        """The register referenced by this alias."""

        self.offset: int = offset
        """'The offset into the referenced register."""

    @property
    def mask(self) -> int:
        mask = (1 << self.size * 8) - 1
        mask <<= self.offset * 8

        return mask

    def extract(self, emulator: emulators.Emulator) -> None:
        self.reference.extract(emulator)

        value = self.reference.get_content() & self.mask
        value >>= self.offset * 8

        self.set_content(value)
        self.set_type(self.reference.get_type())
        self.set_label(self.reference.get_label())

    def apply(self, emulator: emulators.Emulator) -> None:
        value = self.reference.get_content()
        value = (value & ~self.mask) + self.get_content()

        self.reference.set_content(value)
        self.reference.set_type(self.get_type())
        self.reference.set_label(self.get_label())


class Memory(Stateful, Value, dict):
    """A memory region.

    This dictionary maps integer offsets from the base ``address`` to ``Value``
    classes.
    """

    def __init__(self, address: int, size: int, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self.address: int = address
        """The start address of this memory region."""

        self.size: int = size
        """The size address of this memory region."""

    def to_bytes(self, byteorder: platforms.Byteorder) -> bytes:
        """Convert this memory region into a byte string.

        Missing/undefined space will be filled with zeros.

        Arguments:
            byteorder: Byteorder for conversion to raw bytes.

        Returns:
            Bytes for this object with the given byteorder.
        """

        result = b"\x00" * self.size
        for offset, value in self.items():
            data = value.get_content()
            result = (
                result[:offset]
                + data.to_bytes(byteorder=byteorder)
                + result[offset + value.size :]
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

    def _is_safe(self, value: Value):
        if (self.get_used() + value.get_size()) > self.get_capacity():
            raise ValueError("Stack is full")

    def apply(self, emulator: emulators.Emulator) -> None:
        emulator.write_memory(
            self.address, self.to_bytes(byteorder=emulator.platform.byteorder)
        )

    def extract(self, emulator: emulators.Emulator) -> None:
        raise NotImplementedError("extracting memory not yet implemented")


class IntegerValue(Value):
    def __init__(
        self, integer: int, size: int, label: str, signed: bool = True
    ) -> None:
        if size == 8:
            if signed:
                self._type = ctypes.c_int64
            else:
                self._type = ctypes.c_uint64
        elif size == 4:
            if signed:
                self._type = ctypes.c_int32
            else:
                self._type = ctypes.c_uint32
        elif size == 2:
            if signed:
                self._type = ctypes.c_int16
            else:
                self._type = ctypes.c_uint16
        elif size == 1:
            if signed:
                self._type = ctypes.c_int8
            else:
                self._type = ctypes.c_uint8
        else:
            raise NotImplementedError(f"{size}-bit integers are not yet implemented")
        self._content = integer
        self._label = label
        self._size = size

    def get_size(self) -> int:
        return self._size

    def to_bytes(self, byteorder: platforms.Byteorder) -> bytes:
        if byteorder == platforms.Byteorder.LITTLE:
            return self._content.to_bytes(self._size, byteorder="little")
        elif byteorder == platforms.Byteorder.BIG:
            return self._content.to_bytes(self._size, byteorder="big")
        else:
            raise NotImplementedError("middle endian integers are not yet implemented")


class BytesValue(Value):
    def __init__(self, content: typing.Union[bytes, bytearray], label: str) -> None:
        self._content = bytes(content)
        self._label = label
        self._size = len(self._content)
        self._type = ctypes.c_ubyte * self._size

    def get_size(self) -> int:
        return self._size

    def to_bytes(self, byteorder: platforms.Byteorder) -> bytes:
        return self._content


class Stack(Memory):
    @classmethod
    @abc.abstractmethod
    def get_platform(cls) -> platforms.Platform:
        pass

    @abc.abstractmethod
    def get_pointer(self) -> int:
        pass

    @abc.abstractmethod
    def get_alignment(self) -> int:
        pass

    @abc.abstractmethod
    def push(self, value: Value) -> int:
        pass

    def push_integer(self, integer: int, size: int, label: str) -> int:
        value = IntegerValue(integer, size, label)
        return self.push(value)

    def push_bytes(self, content: typing.Union[bytes, bytearray], label: str) -> int:
        value = BytesValue(content, label)
        return self.push(value)

    def push_ctype(self, content, label: str) -> int:
        value = Value.from_ctypes(content, label)
        return self.push(value)

    @classmethod
    def for_platform(cls, platform: platforms.Platform):
        try:
            return utils.find_subclass(
                cls,
                lambda x: x.get_platform().architecture == platform.architecture
                and x.get_platform().byteorder == platform.byteorder,
            )
        except ValueError:
            raise ValueError(f"No stack for {platform}")


class DescendingStack(Stack):
    def push(self, value: Value) -> int:
        self._is_safe(value)
        offset = (self.get_capacity() - 1) - self.get_used()
        self[offset] = value
        return offset


class x86_64Stack(DescendingStack):
    @classmethod
    def get_platform(cls) -> platforms.Platform:
        return platforms.Platform(
            platforms.Architecture.X86_64, platforms.Byteorder.LITTLE
        )

    def get_pointer(self) -> int:
        return ((self.address + self.size) - self.get_used() - 8) & 0xFFFFFFFFFFFFFFF0

    def get_alignment(self) -> int:
        return 16

    @classmethod
    def initialize_stack(cls, argv: typing.List[bytes], *args, **kwargs):
        s = cls(*args, **kwargs)
        argv_address = []
        total_strings_bytes = 0
        for i, arg in enumerate(argv):
            arg_size = len(arg)
            total_strings_bytes += arg_size
            argv_address.append(
                (i, s.push_bytes(bytes(arg, "utf-8"), label=f"argv[{i}]"))
            )

        argc = len(argv)
        total_space = (8 * (argc + 2)) + total_strings_bytes
        padding = 16 - (total_space % 16)
        s.push_bytes(bytes(padding), label="stack alignment padding bytes")
        s.push_integer(0, size=8, label="null terminator of argv array")
        for i, addr in reversed(argv_address):
            s.push_integer(addr, size=8, label=f"pointer to argv[{i}]")
        s.push_integer(argc, size=8, label="argc")
        return s


class Heap(Memory):
    @abc.abstractmethod
    def allocate(self, value: Value) -> int:
        pass

    @abc.abstractmethod
    def free(self, address: int) -> None:
        pass

    def allocate_integer(self, integer: int, size: int, label: str) -> int:
        value = IntegerValue(integer, size, label)
        return self.allocate(value)

    def allocate_bytes(
        self, content: typing.Union[bytes, bytearray], label: str
    ) -> int:
        value = BytesValue(content, label)
        return self.allocate(value)

    def allocate_ctype(self, content, label: str) -> int:
        value = Value.from_ctypes(content, label)
        return self.allocate(value)


class BumpAllocator(Heap):
    @abc.abstractmethod
    def allocate(self, value: Value) -> int:
        self._is_safe(value)
        offset = self.get_used()
        self[offset] = value

    @abc.abstractmethod
    def free(self, address: int) -> None:
        raise NotImplementedError("freeing with a BumpAllocator is not yet implemented")


class Code(Memory):
    pass


class StatefulSet(Stateful, set):
    def extract(self, emulator: emulators.Emulator) -> None:
        for stateful in self:
            stateful.extract(emulator)

    def apply(self, emulator: emulators.Emulator) -> None:
        for stateful in self:
            stateful.apply(emulator)


class Machine(StatefulSet):
    def emulate(self, emulator: emulators.Emulator) -> Machine:
        """Emulate this machine with the given emulator.

        Arguments:
            emulator: An emulator instance on which this machine state should
                run.

        Returns:
            The final system state after emulation.
        """

        self.apply(emulator)

        try:
            emulator.run()
        except exceptions.EmulationStop:
            pass

        return copy.deepcopy(self).extract(emulator)


__all__ = [
    "Stateful",
    "Value",
    "Register",
    "RegisterAlias",
    "Memory",
    "Code",
    "Machine",
]
