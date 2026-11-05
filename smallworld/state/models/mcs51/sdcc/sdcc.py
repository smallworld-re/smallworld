import struct
import typing

from ..... import emulators, exceptions, platforms
from .....platforms.defs.mcs51 import (
    MCS51_CODE_BASE,
    MCS51_IDATA_BASE,
    MCS51_XDATA_BASE,
)
from ...cstd import (
    ArgumentType,
    CStdCallingContext,
    CStdModel,
    VariadicContext,
    signed_int_types,
)
from ...filedesc import FileDescriptorManager as BaseFileDescriptorManager

if typing.TYPE_CHECKING:
    from ...funcptr import FunctionPointer

# SDCC's generic pointers, in the small and large memory models, are three
# bytes: a 16-bit address, then a tag byte naming the space it points into.
# SDCC's own _gptrget tests the tag's top bits in this order.
SDCC_GPTR_CODE = 0x80
SDCC_GPTR_DATA = 0x40
SDCC_GPTR_PDATA = 0x60
SDCC_GPTR_XDATA = 0x00

# Spaces a generic pointer can point into: flat base, size, tag.
_GPTR_SPACES = (
    (MCS51_IDATA_BASE, 0x100, SDCC_GPTR_DATA),
    (MCS51_XDATA_BASE, 0x10000, SDCC_GPTR_XDATA),
    (MCS51_CODE_BASE, 0x10000, SDCC_GPTR_CODE),
)


def sdcc_pointer_to_flat(pointer: int) -> int:
    """Translate an SDCC generic pointer to a flat SmallWorld address.

    The null pointer stays 0, so models can test for it as they do on other
    platforms; SDCC's null is a pointer to XDATA 0x0000.  A pdata pointer
    reaches the first 256 bytes of XDATA.

    Arguments:
        pointer: The three-byte generic pointer, tag in the top byte.

    Returns:
        The flat address it points to.
    """
    if pointer == 0:
        return 0
    address = pointer & 0xFFFF
    tag = (pointer >> 16) & 0xFF
    if tag & SDCC_GPTR_CODE:
        return MCS51_CODE_BASE + address
    if not tag & SDCC_GPTR_DATA:
        return MCS51_XDATA_BASE + address
    if tag & SDCC_GPTR_PDATA == SDCC_GPTR_PDATA:
        return MCS51_XDATA_BASE + (address & 0xFF)
    return MCS51_IDATA_BASE + (address & 0xFF)


def flat_to_sdcc_pointer(address: int) -> int:
    """Translate a flat SmallWorld address to an SDCC generic pointer.

    0 becomes the null pointer, the inverse of :func:`sdcc_pointer_to_flat`.

    Arguments:
        address: A flat address in internal RAM, XDATA or code.

    Returns:
        The three-byte generic pointer, tag in the top byte.

    Raises:
        ConfigurationError: If no generic pointer can reach the address.
    """
    if address == 0:
        return 0
    for base, size, tag in _GPTR_SPACES:
        if base <= address < base + size:
            return (tag << 16) | (address - base)
    raise exceptions.ConfigurationError(
        f"No SDCC generic pointer reaches {hex(address)}"
    )


# Sizes of C types under SDCC on the 8051.  double is float, and size_t is
# unsigned int.
_SIZES = {
    ArgumentType.CHAR: 1,
    ArgumentType.UCHAR: 1,
    ArgumentType.SHORT: 2,
    ArgumentType.USHORT: 2,
    ArgumentType.INT: 2,
    ArgumentType.UINT: 2,
    ArgumentType.SIZE_T: 2,
    ArgumentType.SSIZE_T: 2,
    ArgumentType.LONG: 4,
    ArgumentType.ULONG: 4,
    ArgumentType.FLOAT: 4,
    ArgumentType.DOUBLE: 4,
    ArgumentType.POINTER: 3,
    ArgumentType.LONGLONG: 8,
    ArgumentType.ULONGLONG: 8,
}

_SIGNED = signed_int_types | {ArgumentType.SHORT}

# Where the first argument and the return value go, least significant byte
# first.
_VALUE_REGISTERS = ("dpl", "dph", "b", "acc", "r4", "r5", "r6", "r7")

# Argument locations
_IN_REGISTERS = "registers"
_ON_STACK = "stack"
_IN_PARAMETERS = "parameters"


class FileDescriptorManager(BaseFileDescriptorManager):
    platform = platforms.Platform(platforms.Architecture.MCS51, platforms.Byteorder.BIG)
    abi = platforms.ABI.SDCC


class MCS51SDCCCallingContext(CStdCallingContext):
    """SDCC's default calling convention for the 8051.

    The first argument goes in DPL, DPH, B and A, least significant byte
    first, and in R4-R7 too for a long long; return values come back the same
    way.  Further arguments go in static memory that belongs to the function,
    which SDCC names ``_<function>_PARM_2``, ``_PARM_3`` and so on.  Those
    addresses differ per function and per build, so a model needs them in
    :attr:`parameter_addresses`, as flat addresses; they are in the linker's
    map file.

    A variadic function passes every argument on the stack, as
    ``--stack-auto`` does (see :class:`MCS51SDCCStackAutoCallingContext`);
    set :attr:`variadic` for one.

    Data in memory is little-endian, and pointers are SDCC's three-byte
    generic pointers, which models see as flat addresses (see
    :func:`sdcc_pointer_to_flat`).  This covers the small, medium and large
    memory models; the huge one's banked function pointers are not modeled.
    """

    platform = platforms.Platform(platforms.Architecture.MCS51, platforms.Byteorder.BIG)
    abi = platforms.ABI.SDCC

    #: Whether the function takes variable arguments.
    variadic: bool = False

    #: Flat addresses of the function's static parameters, from its second
    #: argument on (``_<function>_PARM_2``, ``_PARM_3``...).
    parameter_addresses: typing.Sequence[int] = ()

    # Flat addresses of the pdata pages this call's pointer arguments pointed
    # into; see _encode_result.
    _pdata_pages: typing.FrozenSet[int] = frozenset()

    # Integer masks, by SDCC's type sizes.
    _int_sign_mask = 0x8000
    _int_inv_mask = 0xFFFF
    _long_sign_mask = 0x80000000
    _long_inv_mask = 0xFFFFFFFF
    _long_long_sign_mask = 0x8000000000000000
    _long_long_inv_mask = 0xFFFFFFFFFFFFFFFF

    # The base class's register-and-stack layout does not fit SDCC; this
    # class lays out arguments itself, and these only describe the types.
    _four_byte_types = {ArgumentType.LONG, ArgumentType.ULONG}
    _eight_byte_types = {ArgumentType.LONGLONG, ArgumentType.ULONGLONG}
    _four_byte_arg_regs: typing.List[str] = []
    _eight_byte_arg_regs: typing.List[str] = []
    _soft_float = True
    _variadic_soft_float = True
    _floats_are_doubles = False
    _float_arg_regs: typing.List[str] = []
    _double_arg_regs: typing.List[str] = []
    _init_stack_offset = 0
    _align_stack = False
    _eight_byte_reg_size = 1
    _double_reg_size = 1
    _four_byte_stack_size = 4
    _eight_byte_stack_size = 8
    _float_stack_size = 4
    _double_stack_size = 4

    #: Where arguments after the first go.
    _later_arguments = _IN_PARAMETERS

    def set_argument_types(self, argument_types: typing.List[ArgumentType]) -> None:
        self._locations: typing.List[str] = []
        # Stack arguments: bytes from the return address to the argument's
        # end.  Parameters: index into parameter_addresses.
        self._offsets: typing.List[int] = []
        self._stack_depth = 0
        super().set_argument_types(argument_types)

    def add_argument(self, i: int, kind: ArgumentType) -> None:
        if kind not in _SIZES:
            raise exceptions.ConfigurationError(f"Argument {i} has unknown type {kind}")
        if self.variadic or (i > 0 and self._later_arguments == _ON_STACK):
            # Pushed last to first, so earlier arguments sit nearer the
            # return address.
            self._stack_depth += _SIZES[kind]
            self._locations.append(_ON_STACK)
            self._offsets.append(self._stack_depth)
        elif i == 0:
            self._locations.append(_IN_REGISTERS)
            self._offsets.append(0)
        else:
            self._locations.append(_IN_PARAMETERS)
            self._offsets.append(i - 1)

    def _argument_address(self, index: int, emulator: emulators.Emulator) -> int:
        offset = self._offsets[index]
        if self._locations[index] == _ON_STACK:
            # SP points at the return address's high byte.
            sp = emulator.read_register("sp")
            return MCS51_IDATA_BASE + sp - 1 - offset
        if offset >= len(self.parameter_addresses):
            raise exceptions.ConfigurationError(
                f"{self.__class__.__name__} needs the address of argument "
                f"{index + 1}; set parameter_addresses"
            )
        return self.parameter_addresses[offset]

    def _read_bytes(self, index: int, size: int, emulator: emulators.Emulator) -> bytes:
        if self._locations[index] == _IN_REGISTERS:
            return bytes(emulator.read_register(r) for r in _VALUE_REGISTERS[:size])
        return emulator.read_memory(self._argument_address(index, emulator), size)

    def _write_bytes(
        self, index: int, data: bytes, emulator: emulators.Emulator
    ) -> None:
        if self._locations[index] == _IN_REGISTERS:
            for register, byte in zip(_VALUE_REGISTERS, data):
                emulator.write_register(register, byte)
        else:
            emulator.write_memory(self._argument_address(index, emulator), data)

    def get_argument(
        self, index: int, kind: ArgumentType, emulator: emulators.Emulator
    ) -> typing.Union[int, float]:
        data = self._read_bytes(index, _SIZES[kind], emulator)
        value = _decode(kind, data)
        if kind == ArgumentType.POINTER and _is_pdata(data):
            assert isinstance(value, int)
            self._pdata_pages = self._pdata_pages | {value & ~0xFF}
        return value

    def _start_call(self) -> None:
        # A new call: forget the last one's pointer arguments.
        self._pdata_pages = frozenset()

    def _encode_result(self, value: typing.Union[int, float]) -> bytes:
        # pdata is the first page of XDATA, reached through MOVX @Ri, so a
        # pdata pointer and an XDATA pointer can name the same byte, and SDCC
        # compares all three bytes of two pointers.  A flat address does not
        # say which it was; a result in a pdata page a pointer argument
        # pointed into, as one into the argument's object is, is pdata too.
        if (
            self.return_type == ArgumentType.POINTER
            and isinstance(value, int)
            and value & ~0xFF in self._pdata_pages
        ):
            pointer = (SDCC_GPTR_PDATA << 16) | (value - MCS51_XDATA_BASE)
            return pointer.to_bytes(3, "little")
        return _encode(self.return_type, value)

    def set_argument(
        self,
        index: int,
        emulator: emulators.Emulator,
        value: typing.Union[int, float],
    ) -> None:
        kind = self.argument_types[index]
        self._write_bytes(index, _encode(kind, value), emulator)

    def get_varargs(self) -> "MCS51SDCCVariadicContext":
        if not self.variadic:
            raise exceptions.ConfigurationError(
                f"{self.__class__.__name__} is not variadic"
            )
        return MCS51SDCCVariadicContext(self)

    def set_return_value(
        self, emulator: emulators.Emulator, val: typing.Union[int, float]
    ) -> None:
        if self.return_type == ArgumentType.VOID:
            raise exceptions.ConfigurationError("Returning from void function")
        data = self._encode_result(val)
        for register, byte in zip(_VALUE_REGISTERS, data):
            emulator.write_register(register, byte)

    def get_return_value(
        self, emulator: emulators.Emulator
    ) -> typing.Union[int, float, None]:
        if self.return_type == ArgumentType.VOID:
            return None
        size = _SIZES[self.return_type]
        data = bytes(emulator.read_register(r) for r in _VALUE_REGISTERS[:size])
        return _decode(self.return_type, data)

    def set_return_address(
        self, emulator: emulators.Emulator, address: int, push=False
    ) -> None:
        # The return address goes on the stack low byte first, as LCALL
        # pushes it; SP points at its high byte.
        sp = emulator.read_register("sp")
        if push:
            sp = (sp + 2) & 0xFF
            emulator.write_register("sp", sp)
        emulator.write_memory(
            MCS51_IDATA_BASE + sp - 1, int.to_bytes(address & 0xFFFF, 2, "little")
        )

    def function_pointer(
        self,
        address: int,
        argument_types: typing.List[ArgumentType],
        return_type: ArgumentType,
    ) -> "FunctionPointer":
        """Get a callable function pointer, such as a callback a model was given

        SDCC's library declares the callbacks it takes, such as qsort's
        comparator, ``__reentrant``, so they are called with SDCC's reentrant
        convention whatever this one is.  ``address`` is a code address.
        """
        from ...funcptr import FunctionPointer
        from ..sdccstackauto.sdccstackauto import MCS51SDCCStackAutoCallingContext

        return FunctionPointer(
            MCS51_CODE_BASE + address,
            argument_types,
            return_type,
            self.platform,
            context=MCS51SDCCStackAutoCallingContext(),
        )

    def begin_call(
        self,
        emulator: emulators.Emulator,
        address: int,
        args: typing.Sequence[typing.Union[int, float]],
        return_address: int,
    ) -> None:
        # Arguments on the stack sit below the return address, so make room
        # for them before pushing it.
        sp = emulator.read_register("sp")
        emulator.write_register("sp", (sp + self._stack_depth) & 0xFF)
        super().begin_call(emulator, address, args, return_address)

    def end_call(self, emulator: emulators.Emulator) -> None:
        # The caller pops the arguments it put on the stack.
        sp = emulator.read_register("sp")
        emulator.write_register("sp", (sp - self._stack_depth) & 0xFF)

    # The base class routes return values through these; SDCC's go through
    # set_return_value and get_return_value above.

    def _return_4_byte(self, emulator: emulators.Emulator, val: int) -> None:
        for register, byte in zip(_VALUE_REGISTERS, int.to_bytes(val, 4, "little")):
            emulator.write_register(register, byte)

    def _read_return_4_byte(self, emulator: emulators.Emulator) -> int:
        return int.from_bytes(
            bytes(emulator.read_register(r) for r in _VALUE_REGISTERS[:4]), "little"
        )

    def _return_8_byte(self, emulator: emulators.Emulator, val: int) -> None:
        for register, byte in zip(_VALUE_REGISTERS, int.to_bytes(val, 8, "little")):
            emulator.write_register(register, byte)

    def _read_return_8_byte(self, emulator: emulators.Emulator) -> int:
        return int.from_bytes(
            bytes(emulator.read_register(r) for r in _VALUE_REGISTERS), "little"
        )

    def _return_float(self, emulator: emulators.Emulator, val: float) -> None:
        self._return_4_byte(emulator, int.from_bytes(struct.pack("<f", val), "little"))

    def _read_return_float(self, emulator: emulators.Emulator) -> float:
        raw = self._read_return_4_byte(emulator)
        return struct.unpack("<f", raw.to_bytes(4, "little"))[0]

    # SDCC's double is a float.
    _return_double = _return_float
    _read_return_double = _read_return_float

    def read_integer(
        self, address: int, kind: ArgumentType, emulator: emulators.Emulator
    ) -> int:
        """Read an integer, or a generic pointer, out of memory.

        SDCC stores data little-endian, whatever the platform's byte order.
        """
        value = _decode(kind, emulator.read_memory(address, _SIZES[kind]))
        assert isinstance(value, int)
        return value

    def write_integer(
        self,
        address: int,
        intval: int,
        kind: ArgumentType,
        emulator: emulators.Emulator,
    ) -> None:
        """Write an integer, or a generic pointer, to memory."""
        emulator.write_memory(address, _encode(kind, intval))


def _is_pdata(pointer: bytes) -> bool:
    tag = pointer[2]
    return not tag & SDCC_GPTR_CODE and tag & SDCC_GPTR_PDATA == SDCC_GPTR_PDATA


def _decode(kind: ArgumentType, data: bytes) -> typing.Union[int, float]:
    if kind in (ArgumentType.FLOAT, ArgumentType.DOUBLE):
        return struct.unpack("<f", data)[0]
    value = int.from_bytes(data, "little")
    if kind == ArgumentType.POINTER:
        return sdcc_pointer_to_flat(value)
    if kind in _SIGNED and value & (1 << (len(data) * 8 - 1)):
        value -= 1 << (len(data) * 8)
    return value


def _encode(kind: ArgumentType, value: typing.Union[int, float]) -> bytes:
    if kind in (ArgumentType.FLOAT, ArgumentType.DOUBLE):
        if not isinstance(value, float):
            raise exceptions.ConfigurationError(f"Expected a float for {kind}")
        return struct.pack("<f", value)
    if not isinstance(value, int):
        raise exceptions.ConfigurationError(f"Expected an integer for {kind}")
    if kind == ArgumentType.POINTER:
        value = flat_to_sdcc_pointer(value)
    size = _SIZES[kind]
    return (value & ((1 << (size * 8)) - 1)).to_bytes(size, "little")


class MCS51SDCCVariadicContext(VariadicContext):
    """Reads a variadic function's variable arguments off the stack.

    SDCC promotes char arguments to int, and float stays float, since double
    is float.
    """

    def __init__(self, parent: MCS51SDCCCallingContext) -> None:
        super().__init__(parent)
        self._stack_depth = parent._stack_depth

    def get_next_argument(
        self, kind: ArgumentType, emulator: emulators.Emulator
    ) -> typing.Union[int, float]:
        """Get the next argument of an assumed type"""
        return _decode(kind, self._next_argument_bytes(kind, emulator))

    def format_next_pointer(self, emulator: emulators.Emulator) -> str:
        """Get the next argument as a pointer, as printf's %p shows it

        As SDCC's library does: a letter for the space the pointer's tag
        names, then the address in it, with two digits for internal RAM and
        pdata, which are 256 bytes.
        """
        pointer = int.from_bytes(
            self._next_argument_bytes(ArgumentType.POINTER, emulator), "little"
        )
        tag = (pointer >> 16) & 0xFF
        if tag & SDCC_GPTR_CODE:
            space = "C"
        elif tag & SDCC_GPTR_PDATA == SDCC_GPTR_PDATA:
            space = "P"
        elif tag & SDCC_GPTR_DATA:
            space = "I"
        else:
            space = "X"
        if space in ("I", "P"):
            return f"{space}:0x{pointer & 0xFF:02x}"
        return f"{space}:0x{pointer & 0xFFFF:04x}"

    def _next_argument_bytes(
        self, kind: ArgumentType, emulator: emulators.Emulator
    ) -> bytes:
        if kind not in _SIZES:
            raise exceptions.ConfigurationError(f"Unknown argument type {kind}")
        self._stack_depth += _SIZES[kind]
        sp = emulator.read_register("sp")
        address = MCS51_IDATA_BASE + sp - 1 - self._stack_depth
        return emulator.read_memory(address, _SIZES[kind])


class MCS51SDCCModel(MCS51SDCCCallingContext, CStdModel):
    """Base class for C models using SDCC's default 8051 convention"""

    def model(self, emulator: emulators.Emulator) -> None:
        # A model that calls back into the program, as qsort does, re-enters
        # with skip_return set; the call it is in goes on.
        if not self.skip_return:
            self._start_call()
        super().model(emulator)


__all__ = [
    "FileDescriptorManager",
    "MCS51SDCCCallingContext",
    "MCS51SDCCModel",
    "MCS51SDCCVariadicContext",
    "flat_to_sdcc_pointer",
    "sdcc_pointer_to_flat",
]
