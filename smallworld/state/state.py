from __future__ import annotations

import abc
import collections
import copy
import ctypes
import logging as lg
import typing

import claripy

from .. import analyses, emulators, exceptions, logging, platforms, state, utils

logger = lg.getLogger(__name__)


class Stateful(metaclass=abc.ABCMeta):
    """An abstract class whose subclasses represent system state that can be applied to/loaded from an emulator."""

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


CTypesAny = typing.Union[ctypes.Structure, ctypes.Union]
ValueContent = typing.Union[None, int, bytes, claripy.ast.bv.BV, CTypesAny]


class Value(metaclass=abc.ABCMeta):
    """An abstract class whose subclasses all have a tuple of content, type, and label.  Content is the value which must be convertable into bytes. The type is a ctype reprensenting the type of content. Label is a string that is a human label for the object. Any or all are optional."""

    def __init__(self: typing.Any) -> None:
        self._content: ValueContent = None
        self._type: typing.Optional[typing.Any] = None
        self._label: typing.Optional[str] = None

    @abc.abstractmethod
    def get_size(self) -> int:
        """Get the size of this value.

        Returns:
            The number of bytes this value should occupy in memory.
        """

        return 0

    def get_content(self) -> ValueContent:
        """Get the content of this value.

        Returns:
            The content of this value.
        """

        return self._content

    def set_content(self, content: ValueContent) -> None:
        """Set the content of this value.

        Arguments:
            content: The content to which the value will be set.
        """

        self._content = content

    def get_type(self) -> typing.Optional[typing.Any]:
        """Get the type of this value.

        Returns:
            The type of this value.
        """

        return self._type

    def set_type(self, type: typing.Optional[typing.Any]) -> None:
        """Set the type of this value.

        Arguments:
            type: The type value to set.
        """

        self._type = type

    def get_label(self) -> typing.Optional[str]:
        """Get the label of this value.

        Returns:
            The label of this value.
        """

        return self._label

    def set_label(self, label: typing.Optional[str]) -> None:
        """Set the label of this value.

        Arguments:
            type: The label value to set.
        """

        self._label = label

    def get(self) -> ValueContent:
        """A helper to get the content of this value.

        Returns:
            The content of this value.
        """

        return self.get_content()

    def set(self, content: ValueContent) -> None:
        """A helper to set the content of this value.

        Arguments:
            content: The content value to set.
        """

        self.set_content(content)

    def to_symbolic(
        self, byteorder: platforms.Byteorder
    ) -> typing.Optional[claripy.ast.bv.BV]:
        """Convert this value into a symbolic expression

        For an unlabeled value, this will be a bit vector symbol containing the label.
        Otherwise, it will be a bit vector value containing the contents.

        Arguments:
            byteorder: The byte order to use in the conversion.

        Returns:
            Symbolic expression object, or None if both content and label are None
        """

        size = self.get_size()

        if self.get_label() is not None:
            # This has a label; assume we use it.
            label = self.get_label()
            if not isinstance(label, str):
                raise exceptions.ConfigurationError(
                    f"Cannot create a symbol from label of type {type(self._label)}; must be str"
                )

            # Bit vectors are bit vectors; multiply size in bytes by 8
            return claripy.BVS(label, size * 8, explicit_name=True)

        elif self._content is not None:
            content = self._content

            if isinstance(content, claripy.ast.bv.BV):
                # The content is already a symbolic expression
                return content

            if isinstance(content, int):
                # The content is an int; convert to bytes for universal handling
                if byteorder == platforms.Byteorder.BIG:
                    content = content.to_bytes(size, "big")
                else:
                    content = content.to_bytes(size, "little")

            if not isinstance(content, bytes) and not isinstance(content, bytearray):
                # The content is not something I know how to handle.
                raise exceptions.ConfigurationError(
                    f"Cannot create a symbol from content of type {type(self._content)}; "
                    "must be a claripy expression, int, bytes, or bytearray"
                )

            if size == 0:
                raise exceptions.ConfigurationError(
                    "Cannot create a bitvector of size zero"
                )

            if len(content) != size:
                raise exceptions.ConfigurationError(
                    f"Expected size {size}, but content has size {len(content)}"
                )

            return claripy.BVV(bytes(content))

        else:
            return None

    def __getstate__(self):
        # Override default pickling operation
        # The '_type' field is a ctypes class which won't be pickleable.
        # TODO: figure out how to pickle ctypes classes
        state = self.__dict__.copy()
        state["_type"] = None
        return state

    @abc.abstractmethod
    def to_bytes(self) -> bytes:
        """Convert this value into a byte string.

        Returns:
            Bytes for this value.
        """

        return b""

    @classmethod
    def from_ctypes(cls, ctype: CTypesAny, label: str):
        """Load from an existing ctypes value.

        Arguements:
            ctype: The data in ctype form.

        Reutrns:
            The value constructed from ctypes data.
        """

        class CTypeValue(Value):
            def __init__(self, ctype: CTypesAny, label: str):
                self._content = ctype
                self._label = label
                self._type = ctype.__class__

            def __getstate__(self):
                state = self.__dict__.copy()
                del state["_content"]
                del state["_type"]
                return state

            # def __setstate__(self, state):

            def get_size(self) -> int:
                return ctypes.sizeof(self._content)  # type: ignore

            def to_bytes(self) -> bytes:
                return bytes(self._content)  # type: ignore

        return CTypeValue(ctype, label)


class SymbolicValue(Value):
    """A symbolic value

    This value is expressed as a bitvector expression,
    compatible with angr's internal state representation.
    If used with a concrete emulator, it defaults to zeroes.

    Arguments:
        size: The size of the region
        bv: Optional bitvector value
        type: Optional typedef information
        label: An optional metadata label
    """

    def __init__(
        self,
        size: int,
        bv: typing.Optional[claripy.ast.bv.BV],
        type: typing.Optional[typing.Any],
        label: typing.Optional[str],
    ):
        super().__init__()
        self._content = bv
        self._size = size
        self._type = type
        self._label = label

    def get_size(self) -> int:
        return self._size

    def to_bytes(self):
        return b"\0" * self._size


class IntegerValue(Value):
    """An integer value.

    This is useful for using python integers, but passing them to emulators that care about things like width. The type is derived based on the size.

    Arguments:
        size: The size of the integer. Must be 1, 2, 4, 8
        label: An optional metadata label
    """

    def __init__(
        self,
        integer: int,
        size: int,
        label: typing.Optional[str],
        byteorder: platforms.Byteorder,
        signed: bool = True,
    ) -> None:
        super().__init__()
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
        self._byteorder = byteorder

    def get_size(self) -> int:
        return self._size

    @property
    def byteorder(self) -> platforms.Byteorder:
        return self._byteorder

    def to_bytes(self) -> bytes:
        if self._content is None:
            raise ValueError("IntegerValue must have an integer value")
        if not isinstance(self._content, int):
            raise TypeError("IntegerValue is not an integer")
        value = self._content
        if value < 0:
            # Convert signed python into unsigned int containing 2s-compliment value.
            # Python's to_bytes() doesn't do this on its own.
            value = 2 ** (self._size * 8) + value
        if self._byteorder == platforms.Byteorder.LITTLE:
            return value.to_bytes(self._size, byteorder="little")
        elif self._byteorder == platforms.Byteorder.BIG:
            return value.to_bytes(self._size, byteorder="big")
        else:
            raise NotImplementedError("middle endian integers are not yet implemented")


class BytesValue(Value):
    """A bytes value.

    This is for representing a python bytes or bytearray as a value.

    Arguments:
        label: An optional metadata label
    """

    def __init__(
        self, content: typing.Union[bytes, bytearray], label: typing.Optional[str]
    ) -> None:
        super().__init__()
        self._content = bytearray(content)
        self._label = label
        self._size = len(self._content)
        self._type = ctypes.c_ubyte * self._size

    def get_size(self) -> int:
        return self._size

    def to_bytes(self) -> bytes:
        if self._content is None or (
            not isinstance(self._content, bytes)
            and not isinstance(self._content, bytearray)
        ):
            raise ValueError("BytesValue must have a bytes value")
        return bytes(self._content)


class Register(Value, Stateful):
    """An individual register.

    Arguments:
        name: The canonical name of the register.
        size: The size (in bytes) of the register.
    """

    def __init__(
        self,
        name: str,
        size: int = 4,
    ):
        super().__init__()

        self.name: str = name
        """Canonical name."""

        self.size = size
        """Register size in bytes."""

        self.byteorder: typing.Optional[platforms.Byteorder] = None
        """Register platform byteorder. Assigned by CPU constructor."""

    def __str__(self):
        s = f"Reg({self.name},{self.size})="
        x = self.get_content()
        if x is None:
            s = s + "=None"
        elif isinstance(x, int):
            s = s + f"0x{x:x}"
        else:
            s = s + str(type(x))
        return s

    def _register_content_typecheck(
        self, content: ValueContent
    ) -> typing.Union[int, claripy.ast.bv.BV, None]:
        if not (
            isinstance(content, int)
            or isinstance(content, claripy.ast.bv.BV)
            or content is None
        ):
            raise TypeError(
                f"Expected None, int, or claripy expression as content for Register {self.name}, got {type(content)}"
            )
        return content

    def set_content(self, content: ValueContent):
        if content is not None:
            content = self._register_content_typecheck(content)
            if isinstance(content, int) and content < 0:
                logger.warn(
                    f"Converting content {hex(content)} of {self.name} to unsigned."
                )
                content = content + (2 ** (self.size * 8))
            if isinstance(content, claripy.ast.bv.BV):
                if content.size() != self.size * 8:
                    raise ValueError(
                        f"Claripy content had size {content.size()} bits, but expected {self.size * 8} bits"
                    )
        super().set_content(content)

    def get_size(self) -> int:
        return self.size

    def extract(self, emulator: emulators.Emulator) -> None:
        content: typing.Union[int, claripy.ast.bv.BV] = 0
        try:
            content = emulator.read_register_content(self.name)
            if content is not None:
                self.set_content(content)
        except exceptions.SymbolicValueError:
            content = emulator.read_register_symbolic(self.name)
            if content is not None:
                self.set_content(content)
        except exceptions.UnsupportedRegisterError:
            return

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
        content = self.get_content()
        content = self._register_content_typecheck(content)
        if content is not None:
            emulator.write_register_content(self.name, content)
        if self.get_type() is not None:
            emulator.write_register_type(self.name, self.get_type())
        if self.get_label() is not None:
            emulator.write_register_label(self.name, self.get_label())

    def to_bytes(self) -> bytes:
        value = self.get_content()

        if value is None:
            # Default to zeros if no value present.
            return b"\0" * self.size
        elif isinstance(value, claripy.ast.bv.BV):
            raise exceptions.SymbolicValueError(
                "Cannot convert a symbolic expression to bytes"
            )
        elif isinstance(value, bytes):
            # This never happens, but let's keep mypy happy
            return value
        elif self.byteorder == platforms.Byteorder.LITTLE:
            return value.to_bytes(self.size, byteorder="little")
        elif self.byteorder == platforms.Byteorder.BIG:
            return value.to_bytes(self.size, byteorder="big")
        else:
            raise ValueError(f"unsupported byteorder {self.byteorder}")


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

    def get_content(self) -> ValueContent:
        r = self.reference.get_content()
        if r is None:
            return r
        value = self.reference.get_content()
        if value is not None:
            if isinstance(value, int):
                value = value & self.mask
                value >>= self.offset * 8
            elif isinstance(value, claripy.ast.bv.BV):
                lo = self.offset * 8
                hi = lo + self.size * 8 - 1
                value = claripy.simplify(value[hi:lo])
            else:
                raise TypeError(f"Unexpected register content {type(value)}")
        return value

    def set_content(self, content: ValueContent) -> None:
        if content is not None:
            if isinstance(content, int):
                if content < 0:
                    logger.warn(
                        f"Converting content {hex(content)} of {self.name} to unsigned."
                    )
                    content = content + (2 ** (self.size * 8))

            elif isinstance(content, claripy.ast.bv.BV):
                # Bitvectors can only interoperate with bitvectors of the same size.
                content = claripy.ZeroExt(
                    self.reference.size * 8 - self.size * 8, content
                )

            else:
                raise TypeError(
                    f"Can only accept None, int, or BV, not {type(content)}"
                )

            value = self.reference.get_content()
            value = self._register_content_typecheck(value)
            if value is None:
                value = 0

            # mypy completely loses the plot trying to determine type for content
            content = content << (self.offset * 8)  # type: ignore[operator]
            value = (value & ~self.mask) | content
            if isinstance(value, claripy.ast.bv.BV):
                value = claripy.simplify(value)

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


class FixedRegister(Register):
    """A Register that holds a fixed value, and should not be set.

    A number of ISAs have registers hard-wired to zero.
    It would be nice for the harness author to not have
    to remember to set it each time.

    Arguments:
        name:   Name of the register
        size:   Size of the register in bytes
        value:  Fixed value of the register
    """

    def __init__(
        self,
        name,
        size=4,
        value=0,
    ):
        super().__init__(name, size=size)
        super().set_content(value)

    def set_content(self, value: typing.Optional[typing.Any]):
        raise exceptions.ConfigurationError(
            f"Register {self.name} is fixed; it cannot be set"
        )

    def get_label(self) -> typing.Optional[str]:
        # Fixed registers cannot have labels
        return None

    def set_label(self, label: typing.Optional[str]) -> None:
        # Fixed registers cannot have labels
        pass

    def get_type(self) -> typing.Optional[typing.Any]:
        # Fixed registers do not have types
        return None

    def set_type(self, type: typing.Optional[typing.Any]) -> None:
        # Fixed registers do not have types
        pass

    def extract(self, emulator: emulators.Emulator) -> None:
        # Don't bother extracting content
        pass

    def apply(self, emulator: emulators.Emulator) -> None:
        try:
            super().apply(emulator)
        except exceptions.UnsupportedRegisterError:
            # If the register isn't supported, that's okay
            pass


class StatefulSet(Stateful, collections.abc.MutableSet):
    """A set that holds stateful objects. Applying or extracting the set performs the action of every member of the set."""

    def __init__(self):
        super().__init__()
        self._contents = set()

    def extract(self, emulator: emulators.Emulator) -> None:
        for stateful in self:
            stateful.extract(emulator)

    def apply(self, emulator: emulators.Emulator) -> None:
        for stateful in self:
            logger.debug(
                f"applying state {stateful} of type {type(stateful)} to emulator {emulator}"
            )
            stateful.apply(emulator)

    def __contains__(self, item):
        return item in self._contents

    def __iter__(self):
        return self._contents.__iter__()

    def __len__(self):
        return len(self._contents)

    def add(self, item):
        self._contents.add(item)

    def discard(self, item):
        self._contents.discard(item)

    def members(self, type):
        return set(filter(lambda x: isinstance(x, type), self._contents))


class Machine(StatefulSet):
    """A container for all state needed to begin or resume emulation or
    analysis), including CPU with register values, code, raw memory or
    even stack and heap memory.

    Machines have exit points which are instruction addresses that
    when hit by an emulator will cause it to stop before any side
    effects of that instruction are applied. Similarly, machines have
    bounds which are address ranges. When an address outside of the
    range is hit by the emulator that will cause it to stop before any
    side effects are applied. Note that the start of the range is
    included in the range, but the end is not.

    """

    def __init__(self):
        super().__init__()
        self._bounds = utils.RangeCollection()
        self._exit_points = set()
        self._constraints = list()

    def add_exit_point(self, address: int):
        """Add an exit point to the machine.

        Arguments:
            address: The address to exit on

        """
        self._exit_points.add(address)

    def get_exit_points(self) -> typing.Set[int]:
        """Gets the set of exit points for a machine.

        Returns:
            The set of exit point addresses.
        """
        return self._exit_points

    def add_bound(self, start: int, end: int):
        """Adds a bound to the machine

        Arguments:
            start: the start address of the bound (included in the bound)
            end: the end address of the bound (excluded in the bound)
        """
        self._bounds.add_range((start, end))

    def get_bounds(self) -> typing.List[typing.Tuple[int, int]]:
        """Gets a list of bounds for the machine.


        Returns:
            The list of bounds.
        """
        return list(self._bounds.ranges)

    def add_constraint(self, expr: claripy.ast.bool.Bool) -> None:
        """Add a constraint to the environment

        A constraint is an expression that
        some emulators can use to limit the possible values
        of unbound variables.
        They will only consider execution states
        where all constraints can evaluate to True.

        Constraints must be Boolean expressions;
        the easiest form is the equality or inequality
        of two bitvector expressions.

        You can get the variable representing
        a labeled Value via its `to_symbolic()` method.
        Note that Values with both a label and content
        already have a constraint binding the label's
        variable to the content.

        Arguments:
            expr: The constraint expression to add
        """
        if not isinstance(expr, claripy.ast.bool.Bool):
            raise TypeError(f"expr is a {type(expr)}, not a Boolean expression")

        self._constraints.append(expr)

    def get_constraints(self) -> typing.List[claripy.ast.bool.Bool]:
        """Retrieve all constraints applied to this machine.

        Returns:
            A list of constraint expressions
        """
        return list(self._constraints)

    def _build_solver(self) -> claripy.solvers.SolverHybrid:
        solver = claripy.solvers.SolverHybrid()

        for constraint in self._constraints:
            solver.add(constraint)

        return solver

    def concretize(self, value: ValueContent) -> typing.Optional[bytes]:
        """Concretize a value

        This will convert whatever the value happens to be into bytes.
        If it's a symbolic expression, it will find an assignment
        that satisfies the constraints present in this machine.

        Arguments:
            value: The value to concretize

        Returns:
            A bytes object representing the value, or None if expr was None.
        """
        if value is None:
            return None
        elif isinstance(value, bytes):
            return value
        elif isinstance(value, int):
            return value.to_bytes((value.bit_length() + 7) // 8, "big")
        elif isinstance(value, claripy.ast.bv.BV):
            solver = self._build_solver()
            try:
                (res,) = solver.eval(value, 1)
            except claripy.errors.UnsatError:
                raise exceptions.UnsatError("No assignment given constraints")
            return res.to_bytes((res.bit_length() + 7) // 8, "big")
        else:
            raise TypeError(f"Unexpected value type {type(value)}")

    def concretize_symbols(
        self, expr: claripy.ast.bv.BV
    ) -> typing.Generator[typing.Tuple[str, typing.Optional[bytes]], None, None]:
        """Concretize all symbols present in a symbolic expression.

        This is useful for finding satisfying assignments
        that will allow you to reach this particular state;
        feed all constraint expressions for a state into this function,
        and you will get back assignments for all path-critical labels.

        Arguments:
            expr: The expression for which to find assignments

        Yields:
            Tuples of symbol name, symbol value.
        """
        solver = self._build_solver()
        for leaf in expr.leaf_asts():
            if leaf.op == "BVS":
                try:
                    (res,) = solver.eval(leaf, 1)
                    if res == 0:
                        val = b"\x00"
                    else:
                        val = res.to_bytes((res.bit_length() + 7) // 8, "big")
                    yield (leaf.args[0], val)
                except claripy.errors.UnsatError:
                    yield (leaf.args[0], None)

    def apply(self, emulator: emulators.Emulator) -> None:
        for address in self._exit_points:
            emulator.add_exit_point(address)
        for start, end in self.get_bounds():
            emulator.add_bound(start, end)

        if isinstance(emulator, emulators.ConstrainedEmulator):
            for expr in self._constraints:
                emulator.add_constraint(expr)

        return super().apply(emulator)

    def extract(self, emulator: emulators.Emulator) -> None:
        self._exit_points = emulator.get_exit_points()
        for start, end in emulator.get_bounds():
            self.add_bound(start, end)

        if isinstance(emulator, emulators.ConstrainedEmulator):
            self._constraints = emulator.get_constraints()

        return super().extract(emulator)

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

        machine_copy = copy.deepcopy(self)
        machine_copy.extract(emulator)

        return machine_copy

    def analyze(self, analysis: analyses.Analysis) -> None:
        """Run the given analysis on this machine.

        Arguments:
            analysis: The analysis to run.
        """

        analysis.run(self)

    def step(
        self, emulator: emulators.Emulator
    ) -> typing.Generator[Machine, None, None]:
        """This is a generator that single steps the machine each time it is called.

        Yields:
            A new machine that is the previous one single stepped forward.
        """
        self.apply(emulator)

        while True:
            try:
                emulator.step()
                machine_copy = copy.deepcopy(self)
                machine_copy.extract(emulator)
                yield machine_copy

            except exceptions.EmulationStop:
                logger.debug(
                    "emulation complete; encountered exit point or went out of bounds"
                )
                break
        return None

    def fuzz(
        self,
        emulator: emulators.Emulator,
        input_callback: typing.Callable,
        crash_callback: typing.Optional[typing.Callable] = None,
        always_validate: bool = False,
        iterations: int = 1,
    ) -> None:
        """Fuzz the machine via AFL++.

        Parses the input file path from ``argv[1]`` (the placement AFL uses
        when it substitutes ``@@``) and delegates to :meth:`fuzz_with_file`.
        The concrete backend (unicornafl or styxafl) is selected based on
        the type of ``emulator``.

        Arguments:
            emulator: A :class:`UnicornEmulator` or :class:`StyxEmulator`.
            input_callback: A callback that applies an input to the machine.
                Signature: ``(emulator, input_bytes, persistent_round, data)``
                where ``emulator`` is the same SmallWorld emulator passed in
                here. Return ``False`` to skip the input, ``None``/``True``
                to continue.
            crash_callback: Optional callback to decide whether to record a
                crash. (See backend documentation for the exact signature.)
            always_validate: Whether to run ``crash_callback`` on every run
                or only when the backend reports an error.
            iterations: Number of iterations before forking a new child.
        """
        import argparse

        arg_parser = argparse.ArgumentParser(description="AFL Harness")
        arg_parser.add_argument(
            "input_file", type=str, help="File path AFL will mutate"
        )
        args = arg_parser.parse_args()
        self.fuzz_with_file(
            emulator,
            input_callback,
            args.input_file,
            crash_callback,
            always_validate,
            iterations,
        )

    def fuzz_with_file(
        self,
        emulator: emulators.Emulator,
        input_callback: typing.Callable,
        input_file_path: str,
        crash_callback: typing.Optional[typing.Callable] = None,
        always_validate: bool = False,
        iterations: int = 1,
    ) -> None:
        """Fuzz the machine via AFL++ using the given input file.

        Dispatches to the appropriate AFL bridge based on the emulator type:
        :class:`UnicornEmulator` routes through ``unicornafl``;
        :class:`StyxEmulator` routes through ``styxafl``. The user-supplied
        ``input_callback`` always receives the SmallWorld ``emulator`` as
        its first argument, regardless of backend — use methods like
        :meth:`Emulator.write_memory_content` and :meth:`Emulator.write_code`
        to mutate state.

        Arguments:
            emulator: A :class:`UnicornEmulator` or :class:`StyxEmulator`.
            input_callback: ``(emulator, input_bytes, persistent_round, data)``
                — return ``False`` to skip the input, ``None``/``True`` to
                continue.
            input_file_path: The path of the input file AFL will mutate.
            crash_callback: Optional crash-validation callback. (Backend-
                specific signature; see the bridge documentation.)
            always_validate: Run ``crash_callback`` on every iteration.
            iterations: Iterations before forking a new child.
        """
        if isinstance(emulator, emulators.UnicornEmulator):
            self._fuzz_with_unicorn(
                emulator,
                input_callback,
                input_file_path,
                crash_callback,
                always_validate,
                iterations,
            )
        elif isinstance(emulator, emulators.StyxEmulator):
            self._fuzz_with_styx(
                emulator,
                input_callback,
                input_file_path,
                crash_callback,
                always_validate,
                iterations,
            )
        else:
            raise RuntimeError(
                "fuzz_with_file requires a UnicornEmulator or StyxEmulator; "
                f"got {type(emulator).__name__}"
            )

    def _fuzz_with_unicorn(
        self,
        emulator: emulators.UnicornEmulator,
        input_callback: typing.Callable,
        input_file_path: str,
        crash_callback: typing.Optional[typing.Callable],
        always_validate: bool,
        iterations: int,
    ) -> None:
        try:
            import unicornafl
        except ImportError:
            raise RuntimeError(
                "missing `unicornafl` - afl++ must be installed manually from source"
            )

        self.apply(emulator)

        # In persistent mode (iterations > 1) a single forked child runs many
        # inputs back-to-back, so any state a run mutates bleeds into later
        # inputs -- giving non-deterministic coverage and phantom crashes (AFL
        # "stability" collapses). unicornafl restores nothing here, and it cannot
        # see smallworld's Python-side model state (e.g. a BumpAllocator's
        # offset) at all. So snapshot the post-apply state once (registers,
        # writable memory, and the Python state of resettable objects) and
        # restore it before every iteration after the first (iteration 0 runs on
        # the freshly forked child, which is already clean).
        # Local import: heap.py imports from this module, so importing Heap at
        # module scope would be circular.
        from .memory.heap import Heap

        _snap: typing.Dict[str, typing.Any] = {}
        if iterations > 1:
            _snap["ctx"] = emulator.engine.context_save()
            _snap["mem"] = {
                addr: bytes(emulator.engine.mem_read(addr, end - addr + 1))
                for (addr, end, perm) in emulator.engine.mem_regions()
                if perm & 0x2  # UC_PROT_WRITE: read-only code never changes
            }
            _snap["pystate"] = [
                (obj, copy.deepcopy(obj.__dict__))
                for obj in self
                if isinstance(obj, Heap)
            ]

        def _reset() -> None:
            emulator.engine.context_restore(_snap["ctx"])
            for addr, content in _snap["mem"].items():
                emulator.engine.mem_write(addr, content)
            for obj, state in _snap["pystate"]:
                obj.__dict__.clear()
                obj.__dict__.update(copy.deepcopy(state))

        def _adapter(_uc, input_bytes, persistent_round, data):
            if _snap and persistent_round > 0:
                _reset()
            return input_callback(emulator, input_bytes, persistent_round, data)

        unicornafl.uc_afl_fuzz(
            uc=emulator.engine,
            input_file=input_file_path,
            place_input_callback=_adapter,
            exits=emulator.get_exit_points(),
            validate_crash_callback=crash_callback,
            always_validate=always_validate,
            persistent_iters=iterations,
        )

    def _fuzz_with_styx(
        self,
        emulator: emulators.StyxEmulator,
        input_callback: typing.Callable,
        input_file_path: str,
        crash_callback: typing.Optional[typing.Callable],
        always_validate: bool,
        iterations: int,
    ) -> None:
        try:
            import styxafl
        except ImportError:
            raise RuntimeError(
                "missing `styxafl` - install smallworld with the [emu-styx] extra "
                "(built from source via the nix flake)"
            )

        self.apply(emulator)

        def _adapter(_processor, input_bytes, persistent_round, data):
            return input_callback(emulator, input_bytes, persistent_round, data)

        styxafl.styx_afl_fuzz(
            processor=emulator.get_processor(),
            input_file=input_file_path,
            place_input_callback=_adapter,
            exits=list(emulator.get_exit_points()),
            validate_crash_callback=crash_callback,
            always_validate=always_validate,
            persistent_iters=iterations,
        )

    def symbolic_emulate(
        self, emulator: emulators.SymbolicEmulator
    ) -> typing.Generator[Machine, None, None]:
        """Symbolically execute this machine with the given emulator.

        Arguments:
            emulator: An emulator instance on which this machine state should
                run,

        Yields:
            All possible system states after emulation
        """

        assert isinstance(emulator, emulators.Emulator)

        self.apply(emulator)
        try:
            emulator.run()
        except exceptions.EmulationStop:
            pass

        for emu in emulator.get_active_states():
            machine_copy = copy.deepcopy(self)
            machine_copy.extract(emu)
            yield machine_copy

        for emu in emulator.get_deadended_states():
            machine_copy = copy.deepcopy(self)
            machine_copy.extract(emu)
            yield machine_copy

    def get_symbolic_states(
        self, emulator: emulators.SymbolicEmulator
    ) -> typing.Generator[Machine, None, None]:
        """Get a Machine for each active state tracked by a symbolic emulator

        Symbolic execution allows an emulator to consider multiple states at once,
        one for each path the program could possibly take.
        This function yields a Machine for each such state

        Arguments:
            emulator: The symbolic emulator to examine

        Yields:
            One Machine for each active state tracked by the emulator
        """
        for emu in emulator.get_active_states():
            machine = copy.deepcopy(self)
            machine.extract(emu)
            yield machine

    def get_cpus(self):
        """Gets a list of :class:`~smallworld.state.cpus.cpu.CPU` attached to this machine.

        Returns:
            A list of objects that subclass :class:`~smallworld.state.cpus.cpu.CPU` attached to this machin.
        """
        return [i for i in self if issubclass(type(i), state.cpus.cpu.CPU)]

    def get_elfs(self):
        return [i for i in self if issubclass(type(i), state.memory.ElfExecutable)]

    def get_platforms(self):
        """Gets a set of platforms for the :class:`~smallworld.state.cpus.cpu.CPU` (s) attached to this machine.

        Returns:
            A set of platforms for the :class:`~smallworld.state.cpus.cpu.CPU` (s) attached to this machin.

        """
        return set([i.get_platform() for i in self.get_cpus()])

    def get_cpu(self):
        """Gets the :class:`~smallworld.state.cpus.cpu.CPU` attached to this machine. Throws an exception if the machine has more than one.

        Raises:
            ConfigurationError: if the machine has more than one :class:`~smallworld.state.cpus.cpu.CPU`

        Returns:
            The :class:`~smallworld.state.cpus.cpu.CPU` attached to this machine.
        """
        cpus = self.get_cpus()
        if len(cpus) != 1:
            raise exceptions.ConfigurationError("You have more than one CPU")
        return cpus[0]

    def get_elf(self):
        elfs = self.get_elfs()
        if len(elfs) != 1:
            raise exceptions.ConfigurationError("You have more than one ELF")
        return elfs[0]

    def get_platform(self):
        """Gets the platform of the :class:`~smallworld.state.cpus.cpu.CPU` (s) attached to this machine. Throws an exception if the machine has more than one.

        Raises:
            ConfigurationError: if the machine has more than one platform

        Returns:
            The platform for the :class:`~smallworld.state.cpus.cpu.CPU` (s) attached to this machine.
        """
        platforms = self.get_platforms()
        if len(platforms) != 1:
            raise exceptions.ConfigurationError("You have more than one platform")
        return platforms.pop()

    def read_memory(self, address: int, size: int) -> typing.Optional[bytes]:
        """Read bytes out of memory if available.

        Arguments:
            address: start address of read.
            size: number of bytes to read.

        Returns:
            the bytes read, or None if unavailable.
        """
        for m in self:
            if issubclass(type(m), state.memory.Memory):
                for po, v in m.items():
                    if m.address + po <= address <= m.address + po + v.get_size():
                        c = m[po].get()
                        o = address - (m.address + po)
                        return c[o : o + size]
        return None


__all__ = [
    "Stateful",
    "Value",
    "IntegerValue",
    "BytesValue",
    "SymbolicValue",
    "Register",
    "RegisterAlias",
    "FixedRegister",
    "Machine",
]
