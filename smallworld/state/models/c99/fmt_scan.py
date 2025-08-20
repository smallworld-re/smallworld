import abc
import re
import struct

from ....emulators import Emulator
from ....platforms import Byteorder
from ..cstd import ArgumentType, CStdModel, VariadicContext
from ..filedesc import FileDescriptor


class FormatConversionError(Exception):
    pass


class InputEndedError(Exception):
    pass


class Intake(metaclass=abc.ABCMeta):
    """Abstract class for input stream

    The format scan algorithms need to scan both files
    and strings.  I don't want to write two models.
    """

    def __init__(self):
        self.cursor = 0

    @abc.abstractmethod
    def peek(self) -> str:
        raise NotImplementedError()

    @abc.abstractmethod
    def push(self, data: str) -> None:
        raise NotImplementedError()

    @abc.abstractmethod
    def pop(self) -> None:
        raise NotImplementedError()


class FileIntake(Intake):
    """Input stream backed by a file

    That is, a file modeled by the stdio models.
    """

    def __init__(self, file: FileDescriptor):
        super().__init__()
        self.file = file

    def peek(self) -> str:
        data = self.file.read(1, ungetc=True)
        if len(data) == 0:
            raise InputEndedError()

        self.file.ungetc(data[0])

        if data == b"\0":
            raise InputEndedError()

        return data.decode("utf-8")

    def push(self, data: str) -> None:
        raw = data.encode("utf-8")
        for char in reversed(raw):
            self.file.ungetc(char)

        self.cursor -= len(data)

    def pop(self) -> None:
        self.file.read(1, ungetc=True)
        self.cursor += 1


class StringIntake(Intake):
    """Input stream backed by memory.

    Data is read on-demand from the emulator
    """

    def __init__(self, address: int, emulator: Emulator):
        super().__init__()
        self.address = address
        self.emulator = emulator

    def peek(self) -> str:
        data = self.emulator.read_memory(self.address + self.cursor, 1)
        if data == b"\0":
            raise InputEndedError()
        return data.decode("utf-8")

    def push(self, data: str) -> None:
        self.cursor -= len(data)

    def pop(self) -> None:
        self.cursor += 1


# Conversion specifiers:
#
# Group 1: Zero or one '*' flags
#
# Group 2: Zero or one maximum width specifiers
#
# Group 3: Zero or one length specifiers
#
# Group 4: Conversion ID

# Signed decimal int conversion
#
# Allowed Width Specifiers
# - 'hh': char
# - 'h': short
# - '': int
# - 'l': long
# - 'll', 'L', 'q': long long
# - 'z': ssize_t
# - 'j': intmax_t
# - t: ptrdiff_t
#
# Allowed Conversions:
# - 'd', 'i': signed decimal integer
sint_re = re.compile(r"%([*]?)([0-9]*)(hh|h|l|ll|L|q|z|j|t|)(d|i)")

# Unsigned int conversion
#
# Allowed Width Specifiers
# - 'hh': unsigned char
# - 'h': unsigned short
# - '': unsigned int
# - 'l': unsigned long
# - 'll', 'L', 'q': unsigned long long
# - 'z': size_t
# - 'j': intmax_t
# - t: ptrdiff_t
#
# Allowed Conversions:
# - 'o': unsigned octal integer
# - 'u': unsigned decimal integer
# - 'x', 'X': unsigned hexadecimal integer
uint_re = re.compile(r"%([*]?)([0-9]*)(hh|h|l|ll|L|q|z|j|t|)(o|u|x|X)")

# Floating-point conversion
#
# Allowed Width Specifiers
# - '': float
# - 'l': double
# - 'll', 'L', 'q': long double
#
# Allowed Conversions:
# - 'e', 'E', 'f', 'g', 'G', 'a', 'A': signed floating-point
float_re = re.compile(r"%([*]?)([0-9]*)(l|ll|L|q|)(e|E|f|g|a)")

# Character conversion
#
# Allowed Width Specifiers
# - '': char
# - 'l': wchar_t
#
# Allowed Conversions
# - 'c': Character
char_re = re.compile(r"%([*]?)([0-9]*)(l|)(c)")

# String conversion
#
# Allowed Width Specifiers:
# - '': char
# - 'l': wchar_t
#
# Allowed Conversions:
# - 's': String
string_re = re.compile(r"%([*]?)([0-9]*)(l|)(s)")

# Constrained String Conversion
#
# Allowed Width Specifiers:
# - '': char
# - 'l': wchar_t
#
# Allowed conversions:
# - '[.*]': Constrained string; values between '[' and ']' are allowed characters.
# - '[^.*]': Constrained string; values between '[^' and ']' are forbidden characters.

# Special case to detect '%[]]' and '%[^]]'
# These will satisfy the general regexes, but will match
# on '[]' or '[^]', which isn't correct.
brace_re = re.compile(r"%([*]?)([0-9]*)(l|)\[([\^]?\])\]")
constrained_re = re.compile(r"%([*]?)([0-9]*)(l|)\[([\^]?[\]]?[^\]]*)\]")

# Pointer Conversion
#
# Allowed Width Specifiers:
# - '': void *
#
# Allowed Conversions:
# - 'p': Pointer
pointer_re = re.compile(r"%([*]?)()([0-9]*)(p)")

# Length of current input
#
# Allowed Width Specifiers
# - 'hh': char
# - 'h': short
# - '': int
# - 'l': long
# - 'll', 'L', 'q': long long
# - 'z': ssize_t
# - 'j': intmax_t
# - 't': ptrdiff_t
#
# Allowed Conversions
# - 'n': Store number of characters consumed to this point.
length_re = re.compile(r"%([*]?)(hh|h|l|ll|z|j|t|)([0-9]*)(n)")

# Percent sign
percent_re = re.compile(r"%%")


def handle_sint(
    intake: Intake, varargs: VariadicContext, m: re.Match, emulator: Emulator
) -> bool:
    flags = m.group(1)
    maxwidth = -1 if m.group(2) == "" else int(m.group(2))
    length = m.group(3)

    strval = ""

    while True:
        try:
            char = intake.peek()
        except InputEndedError:
            return False

        if char.isspace():
            intake.pop()
        else:
            break

    while maxwidth == -1 or len(strval) < maxwidth:
        try:
            char = intake.peek()
        except InputEndedError:
            break

        if strval == "" and char in ("+", "-"):
            strval += char
            intake.pop()
        elif char in "0123456789":
            strval += char
            intake.pop()
        else:
            break

    if strval == "":
        return False

    if flags == "*":
        intake.push(strval)
        return True

    intval = int(strval)
    if length in ("ll", "L", "q") and intval > (2**63):
        intval &= varargs._long_long_inv_mask & ~varargs._long_long_sign_mask
    elif intval > (2 ** ((varargs.platdef.address_size * 8) - 1)):
        intval &= varargs._long_inv_mask & ~varargs._long_sign_mask

    if intval < 0:
        intval *= -1
        intval = (intval ^ varargs._long_long_inv_mask) + 1

    arg = varargs.get_next_argument(ArgumentType.POINTER, emulator)

    assert isinstance(arg, int)

    if length == "hh":
        intval &= 0xFF
        width = 1
    elif length == "h":
        intval &= 0xFFFF
        width = 2
    elif length == "":
        intval &= varargs._int_inv_mask
        width = 4
    elif length in ("l", "z"):
        intval &= varargs._long_inv_mask
        width = 4 if ArgumentType.LONG in varargs._four_byte_types else 8
    elif length in ("ll", "L", "q"):
        intval &= varargs._long_long_inv_mask
        width = 8
    elif length == "j":
        raise NotImplementedError("Type 'intmax_t' not handled")
    elif length == "t":
        raise NotImplementedError("Type 'ptrdiff_t' not handled")
    else:
        raise FormatConversionError(f"Unknown type specifier {length}")

    if varargs.platform.byteorder == Byteorder.LITTLE:
        byteval = intval.to_bytes(width, "little")
    else:
        byteval = intval.to_bytes(width, "big")

    emulator.write_memory(arg, byteval)

    return True


def handle_uint(
    intake: Intake, varargs: VariadicContext, m: re.Match, emulator: Emulator
) -> bool:
    flags = m.group(1)
    maxwidth = -1 if m.group(2) == "" else int(m.group(2))
    length = m.group(3)
    conversion = m.group(4).lower()

    strval = ""

    while True:
        char = intake.peek()
        if char.isspace():
            intake.pop()
        else:
            break

    while maxwidth == -1 or len(strval) < maxwidth:
        try:
            char = intake.peek()
        except InputEndedError:
            break
        if conversion == "x" and char in ("x", "X") and strval == "0":
            strval += char
            intake.pop()
        elif conversion == "x" and char in "0123456789abcdefABCDEF":
            strval += char
            intake.pop()
        elif conversion == "u" and char in "0123456789":
            strval += char
            intake.pop()
        elif conversion == "o" and char in "01234567":
            strval += char
            intake.pop()
        else:
            break

    if strval == "":
        return False

    if flags == "*":
        intake.push(strval)
        return True

    if conversion == "o":
        intval = int(strval, 8)
    elif conversion == "u":
        intval = int(strval)
    elif conversion == "x":
        intval = int(strval, 16)

    arg = varargs.get_next_argument(ArgumentType.POINTER, emulator)

    assert isinstance(arg, int)

    if length == "hh":
        intval &= 0xFF
        width = 1
    elif length == "h":
        intval &= 0xFFFF
        width = 2
    elif length == "":
        intval &= varargs._int_inv_mask
        width = 4
    elif length in ("l", "z"):
        intval &= varargs._long_inv_mask
        width = 4 if ArgumentType.LONG in varargs._four_byte_types else 8
    elif length in ("ll", "L", "q"):
        intval &= varargs._long_long_inv_mask
        width = 8
    elif length == "j":
        raise NotImplementedError("Type 'intmax_t' not handled")
    elif length == "t":
        raise NotImplementedError("Type 'ptrdiff_t' not handled")
    else:
        raise FormatConversionError(f"Unknown type specifier {length}")

    if varargs.platform.byteorder == Byteorder.LITTLE:
        byteval = intval.to_bytes(width, "little")
    else:
        byteval = intval.to_bytes(width, "big")
    emulator.write_memory(arg, byteval)

    return True


def handle_float(
    intake: Intake, varargs: VariadicContext, m: re.Match, emulator: Emulator
) -> bool:
    flags = m.group(1)
    maxwidth = -1 if m.group(2) == "" else int(m.group(2))
    length = m.group(3)

    found_dot = False
    found_sci = False
    strval = ""
    fixedval = ""

    # NOTE: This will reject hexadecimal floats without a specific error.
    # If _anyone_ finds a legit use of hex floats since 1999, please let me know.
    # I'd be most curious to see.

    while True:
        try:
            char = intake.peek()
        except InputEndedError:
            return False

        if char.isspace():
            intake.pop()
        else:
            break

    while maxwidth == -1 or len(strval) < maxwidth:
        try:
            char = intake.peek()
        except InputEndedError:
            break

        if "infinity".startswith(strval + char):
            strval += char
            intake.pop()
        elif "INFINITY".startswith(strval + char):
            strval += char
            intake.pop()
        elif "nan".startswith(strval + char):
            strval += char
            intake.pop()
        elif "NAN".startswith(strval + char):
            strval += char
            intake.pop()
        elif "-infinity".startswith(strval + char):
            strval += char
            intake.pop()
        elif "-INFINITY".startswith(strval + char):
            strval += char
            intake.pop()
        elif "-nan".startswith(strval + char):
            strval += char
            intake.pop()
        elif "-NAN".startswith(strval + char):
            strval += char
            intake.pop()
        elif (strval == "" or strval[-1] in ("e", "E")) and char in ("+", "-"):
            strval += char
            intake.pop()
        elif not found_dot and not found_sci and char == ".":
            found_dot = True
            strval += char
            intake.pop()
        elif not found_sci and char in ("e", "E"):
            # So, scientific notation is a pain,
            # because an invalid scientific number can be prefixed by a valid fixed-point number.
            # Remember what came before; we'll need to restore back to it.
            found_sci = True
            fixedval = strval
            strval += char
            intake.pop()
        elif char in "0123456789":
            strval += char
            intake.pop()
        else:
            break

    if strval == "":
        return False

    if strval[-1] in ("e", "E"):
        # C accepts scientific notation with no exponent.
        # Python does not.
        strval += "0"

    try:
        floatval = float(strval)
    except ValueError:
        if fixedval == "":
            return False
        try:
            intake.push(strval[len(fixedval) :])
            floatval = float(fixedval)
        except ValueError:
            intake.push(fixedval)
            return False

    if flags == "*":
        return True

    endian = ">" if varargs.platform.byteorder == Byteorder.BIG else "<"

    if length == "":
        byteval = struct.pack(f"{endian}f", floatval)
    elif length == "l":
        byteval = struct.pack(f"{endian}d", floatval)
    elif length == "L":
        raise NotImplementedError("long doubles not handled")
    else:
        raise FormatConversionError(f"Unknown type specifier {length}")

    arg = varargs.get_next_argument(ArgumentType.POINTER, emulator)

    assert isinstance(arg, int)

    emulator.write_memory(arg, byteval)

    return True


def handle_char(
    intake: Intake, varargs: VariadicContext, m: re.Match, emulator: Emulator
) -> bool:
    flags = m.group(1)
    maxwidth = 1 if m.group(2) == "" else int(m.group(2))
    length = m.group(3)

    if length == "l":
        raise NotImplementedError("wchar_t not handled")
    elif length != "":
        raise FormatConversionError(f"Unknown type specifier {length}")

    strval = ""

    while len(strval) < maxwidth:
        try:
            char = intake.peek()
        except InputEndedError:
            break

        strval += char
        intake.pop()

    if flags == "*":
        return True

    byteval = strval.encode("utf-8")

    arg = varargs.get_next_argument(ArgumentType.POINTER, emulator)

    assert isinstance(arg, int)

    emulator.write_memory(arg, byteval)

    return True


def handle_string(
    intake: Intake, varargs: VariadicContext, m: re.Match, emulator: Emulator
) -> bool:
    flags = m.group(1)
    maxwidth = -1 if m.group(2) == "" else int(m.group(2))
    length = m.group(3)

    if length == "l":
        raise NotImplementedError("wchar_t not handled")
    elif length != "":
        raise FormatConversionError(f"Unknown type specifier {length}")

    strval = ""

    while True:
        try:
            char = intake.peek()
        except InputEndedError:
            return False

        if char.isspace():
            intake.pop()
        else:
            break

    while maxwidth == -1 or len(strval) < maxwidth:
        try:
            char = intake.peek()
        except InputEndedError:
            break

        if not char.isspace():
            strval += char
            intake.pop()
        else:
            break

    if flags == "*":
        return True

    byteval = strval.encode("utf-8")
    byteval += b"\0"

    arg = varargs.get_next_argument(ArgumentType.POINTER, emulator)

    assert isinstance(arg, int)

    emulator.write_memory(arg, byteval)

    return True


def handle_constrained(
    intake: Intake, varargs: VariadicContext, m: re.Match, emulator: Emulator
) -> bool:
    flags = m.group(1)
    maxwidth = -1 if m.group(2) == "" else int(m.group(2))
    length = m.group(3)
    conversion = m.group(4)

    if length == "l":
        raise NotImplementedError("wchar_t not handled")
    elif length != "":
        raise FormatConversionError(f"Unknown type specifier {length}")

    if conversion[0] == "^":
        invert = True
        conversion = conversion[1:]

    strval = ""
    while maxwidth == -1 or len(strval) < maxwidth:
        try:
            char = intake.peek()
        except InputEndedError:
            break

        if invert and char not in conversion:
            strval += char
            intake.pop()
        elif not invert and char in conversion:
            strval += char
            intake.pop()
        else:
            break

    if flags == "*":
        return True

    byteval = strval.encode("utf-8")
    byteval += b"\0"

    arg = varargs.get_next_argument(ArgumentType.POINTER, emulator)

    assert isinstance(arg, int)

    emulator.write_memory(arg, byteval)

    return True


def handle_pointer(
    intake: Intake, varargs: VariadicContext, m: re.Match, emulator: Emulator
) -> bool:
    flags = m.group(1)
    maxwidth = -1 if m.group(2) == "" else int(m.group(2))

    strval = ""

    while True:
        try:
            char = intake.peek()
        except InputEndedError:
            return False

        if char.isspace():
            intake.pop()
        else:
            break

    while maxwidth == -1 or len(strval) < maxwidth:
        try:
            char = intake.peek()
        except InputEndedError:
            break

        if (
            "(nil)".startswith(strval + char)
            or "(NIL)".startswith(strval + char)
            or "0x".startswith(strval + char)
        ):
            strval += char
            intake.pop()
        elif char in "0123456789abcdefABCDEF":
            strval += char
            intake.pop()
        else:
            break

    if strval == "":
        return False

    if flags == "*":
        intake.push(strval)
        return True

    if strval in ("(nil)", "(NIL)"):
        intval = 0
    else:
        try:
            intval = int(strval, 16)
        except ValueError:
            intake.push(strval)
            return False

    arg = varargs.get_next_argument(ArgumentType.POINTER, emulator)

    assert isinstance(arg, int)

    if varargs.platform.byteorder == Byteorder.BIG:
        byteval = intval.to_bytes(varargs.platdef.address_size, "big")
    else:
        byteval = intval.to_bytes(varargs.platdef.address_size, "little")

    emulator.write_memory(arg, byteval)

    return True


def handle_length(
    intake: Intake, varargs: VariadicContext, m: re.Match, emulator: Emulator
) -> bool:
    length = m.group(3)

    intval = intake.cursor

    if length == "hh":
        intval &= 0xFF
        width = 1
    elif length == "h":
        intval &= 0xFFFF
        width = 2
    elif length == "":
        intval &= varargs._int_inv_mask
        width = 4
    elif length in ("l", "z"):
        intval &= varargs._long_inv_mask
        width = 4 if ArgumentType.LONG in varargs._four_byte_types else 8
    elif length in ("ll", "L", "q"):
        intval &= varargs._long_long_inv_mask
        width = 8
    elif length == "j":
        raise NotImplementedError("Type 'intmax_t' not handled")
    elif length == "t":
        raise NotImplementedError("Type 'ptrdiff_t' not handled")
    else:
        raise FormatConversionError(f"Unknown type specifier {length}")

    arg = varargs.get_next_argument(ArgumentType.POINTER, emulator)

    assert isinstance(arg, int)

    if varargs.platform.byteorder == Byteorder.BIG:
        byteval = intval.to_bytes(width, "big")
    else:
        byteval = intval.to_bytes(width, "little")

    emulator.write_memory(arg, byteval)

    return True


def handle_percent(
    intake: Intake, varargs: VariadicContext, m: re.Match, emulator: Emulator
) -> bool:
    return True


def handle_scanf_format(
    model: CStdModel, intake: Intake, fmt: str, emulator: Emulator
) -> int:
    """Process a scanf format string

    This is not an entirely complete model.
    The following features are missing:

    - Decoding for hexadecimal floats
    - intmax_t integers
    - ptrdiff_t integers

    Arguments:
        model: The parent API model
        intake: The intake structure from which to fetch data
        emulator: The emulator to run against

    Returns:
        The number of converted arguments, or -1, as per the scanf family.
    """
    varargs = model.get_varargs()

    orig_fmt = fmt

    handlers = [
        (sint_re, handle_sint),
        (uint_re, handle_uint),
        (float_re, handle_float),
        (char_re, handle_char),
        (string_re, handle_string),
        (brace_re, handle_constrained),
        (constrained_re, handle_constrained),
        (pointer_re, handle_pointer),
        (length_re, handle_length),
        (percent_re, handle_percent),
    ]

    converted = 0
    done = False
    while len(fmt) > 0:
        if fmt[0] == "%":
            # Conversion pattern.  See if we can match
            matched = False
            for regex, handler in handlers:
                m = regex.match(fmt)
                if m is not None:
                    try:
                        if not handler(intake, varargs, m, emulator):
                            done = True
                        elif m.group(1) != "*" and m.group(4)[-1] != "n":
                            converted += 1
                    except FormatConversionError as e:
                        print(f"Bad format conversion: {e.args[0]}")
                        print(orig_fmt)
                        print(" " * (len(orig_fmt) - len(fmt)) + "^")
                        raise e
                    except Exception as e:
                        print(f"Exception processing conversion: {type(e)}: {e}")
                        print(orig_fmt)
                        print(" " * (len(orig_fmt) - len(fmt)) + "^")
                        raise e
                    fmt = fmt[len(m.group(0)) :]
                    matched = True
                    break

            if not matched:
                print("Bad format conversion: Unmatched conversion")
                print(orig_fmt)
                print(" " * (len(orig_fmt) - len(fmt)) + "^")
                raise Exception("Bad format conversion")

            if done:
                break

        elif fmt[0].isspace():
            # Whitespace.  Consume zero or more whitespace characters
            while True:
                char = intake.peek()
                if char.isspace():
                    print("Space")
                    intake.pop()
                else:
                    break
            fmt = fmt[1:]
        else:
            # Normal character.  Consume one character that's an exact match
            char = intake.peek()
            if char == fmt[0]:
                intake.pop()
            else:
                return -1

    return converted


__all__ = ["FileIntake", "StringIntake", "handle_scanf_format"]
