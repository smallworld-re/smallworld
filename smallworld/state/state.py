from __future__ import annotations

import abc
import copy
import ctypes
import typing
import logging as lg

logger = logging.getLogger(__name__)

from .. import analyses, emulators, exceptions, platforms, logging, state

logger = lg.getLogger(__name__)



class Stateful(metaclass=abc.ABCMeta):
    """System state that can be applied to/loaded from an emulator."""

    @abc.abstractmethod
    def extract(self, emulator: emulators.Emulator) -> None:
        """Load state from an emulator.

        Arguments:
            emulator: The emulator from which to load
        """

        pass

    @abc.abstractmethod
    def apply(self, emulator: emulators.Emulator) -> None:
        """Apply state to an emulator.

        Arguments:
            emulator: The emulator to which state should applied.
        """

        pass

    def __hash__(self) -> int:
        return id(self)


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
    def from_ctypes(cls, ctype: typing.Any, label: str):
        """Load from an existing ctypes object."""
        class CTypeValue(Value):
            _type = ctype.__class__
            _label = label
            _content = ctype

            def get_size(self) -> int:
                return ctypes.sizeof(self._content)

            def to_bytes(self, byteorder: platforms.Byteorder) -> bytes:
                return bytes(self._content)

        return CTypeValue()

class EmptyValue(Value):
    """An unconstrained value

    This has a size, label, and type, but has no concrete value.
    This is particularly useful for symbolic analyses with angr.
    If used with Unicorn, it will resolve to a string of zeroes.

    Arguments:
        size: The size of the region
        type: Optional typedef information
        label: An optional metadata label
    """
    def __init__(self, size: int, type: typing.Optional[typing.Any], label: typing.Optional[str]):
        self._size = size
        self._type = type
        self._label = label

    def get_size(self) -> int:
        return self._size

    def to_bytes(self):
        return b'\0' * self._size

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
        try:
            content = emulator.read_register_content(self.name)
            if content is not None:
                self.set_content(content)
        except exceptions.SymbolicValueError:
            pass

        type = emulator.read_register_type(self.name)
        if type is not None:
            self.set_type(type)

        try:
            label = emulator.read_register_label(self.name)
            if label is not None:
                self.set_label(label)
        except exceptions.SymbolicValueError:
            pass


    def apply(self, emulator: emulators.Emulator) -> None:
        if self.get_content() is not None:
            emulator.write_register_content(self.name, self.get_content())
        if self.get_type() is not None:
            emulator.write_register_type(self.name, self.get_type())
        if self.get_label() is not None:
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

    def get_content(self) -> typing.Optional[typing.Any]:
        r = self.reference.get_content()
        if r is None:
            return r
        value = self.reference.get_content() & self.mask
        value >>= self.offset * 8
        return value

    def set_content(self, content: typing.Optional[typing.Any]) -> None:
        if content is not None:
            value = self.reference.get_content()
            if value is  None:
                value = 0
            value = (value & ~self.mask) | content
            self.reference.set_content(value)

    def get_type(self) -> typing.Optional[typing.Any]:
        return self.reference.get_type()

    def set_type(self, type: typing.Optional[typing.Any]) -> None:
        self.reference.set_type(type)

    def get_label(self) -> typing.Optional[str]:
        return self.reference.get_label()

    def set_label(self, label: typing.Optional[str]) -> None:
        self.reference.set_label(label)

    def extract(self, emulator: emulators.Emulator) -> None:
        pass

    def apply(self, emulator: emulators.Emulator) -> None:
        pass


class StatefulSet(Stateful, set):
    def extract(self, emulator: emulators.Emulator) -> None:
        for stateful in self:
            # logger.debug(f"extracting state {stateful} of type {type(stateful)} from {emulator}")
            stateful.extract(emulator)

    def apply(self, emulator: emulators.Emulator) -> None:
        for stateful in self:
            logger.debug(f"applying state {stateful} of type {type(stateful)} to emulator {emulator}")
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
        except exceptions.EmulationBounds:
            pass

        machine_copy = copy.deepcopy(self)
        machine_copy.extract(emulator)

        return machine_copy

    def analyze(self, analysis: analyses.Analysis) -> None:
        """Run the given analysis on this machine.

        Arguments:
            analysis: The analysis to run.
        """

        analysis.run(self)

    def step(self, emulator: emulators.Emulator) -> Machine:
        self.apply(emulator)
        while True:
            try:
                emulator.step()
                machine_copy = copy.deepcopy(self)
                machine_copy.extract(emulator)
                yield machine_copy
            except exceptions.EmulationBounds:
                print("emulation complete; encountered exit point or went out of bounds")
                break
            except Exception as e:
                print(f"emulation ended; raised exception {e}")
                break

    def fuzz(self, emulator: emulators.Emulator, input_callback: typing.Callable,
        crash_callback: typing.Optional[typing.Callable] = None,
        always_validate: bool = False,
        iterations: int = 1,
    ) -> None:
        try:
            import unicornafl
            import argparse
        except ImportError:
            raise RuntimeError("missing `unicornafl` - afl++ must be installed manually from source")

        arg_parser = argparse.ArgumentParser(description="AFL Harness")
        arg_parser.add_argument("input_file", type=str, help="File path AFL will mutate")
        args = arg_parser.parse_args()

        if type(emulator) != emulators.UnicornEmulator:
            raise RuntimeError("you must use a unicorn emulator to fuzz")

        self.apply(emulator)

        unicornafl.uc_afl_fuzz(
                uc=emulator.engine,
                input_file=args.input_file,
                place_input_callback=input_callback,
                exits=emulator.get_exitpoints(),
                validate_crash_callback=crash_callback,
                always_validate=always_validate,
                persistent_iters=iterations,
            )

    def get_cpu(self):
        for i in self:
            if issubclass(type(i), state.cpus.cpu.CPU):
                return i




__all__ = [
    "Stateful",
    "Value",
    "IntegerValue",
    "BytesValue",
    "EmptyValue",
    "Register",
    "RegisterAlias",
    "Machine",
]
