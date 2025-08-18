import re
import struct
import typing

from ....emulators import Emulator
from ....platforms import Byteorder
from ..cstd import ArgumentType, CStdModel, VariadicContext
from .utils import _emu_strlen

# Conversion specifiers:
#
# Group 1: Zero or more flags
#
# Group 2: Zero or one field width specifiers
# - '[0-9]+': Explicit width
# - '*': Next argument is an int storing the width
#
# Group 3: Zero or one precision specifiers
# - '.': Zero precision
# - '.[0-9]+': Explicit precision
# - '.*': Next argument is an int storing the width
# - NOTE: Default precision for floats is six.
#
# Group 4: Unused; part of the precision pattern
#
# Group 5: Zero or one length specifiers
#
# Group 6: Conversion ID

# Signed decimal int conversion
#
# Allowed flags:
# - '0': Justify the field with zeros
# - ' ': Add a space before a positive number
# - '-': Left-justify the field.  Default is right-justify
# - '+': Always include a sign symbol
#
# Allowed lengths:
# - 'hh': char
# - 'h': short
# - '': int
# - 'l': long
# - 'll', 'q': long long
# - 'z', 'Z': ssize_t
# - 'j': intmax_t
# - 't': ptrdiff_t
#
# Allowed conversions:
# - d, i: signed decimal integer
sdecint_re = re.compile(
    "%([0 \\-+]*)([0-9]*|[*])((\\.[0-9]*|\\.[*])?)(hh|h|l|ll|q|z|Z|j|t|)(d|i)"
)

# Unsigned decimal int conversion
#
# Allowed flags:
# - '0': Justify the field with zeros
# - '-': Left-justify the field.  Default is right-justify
#
# Allowed lengths:
# - 'hh': char
# - 'h': short
# - '': int
# - 'l': long
# - 'll', 'q': long long
# - 'z', 'Z': size_t
# - 'j': intmax_t
# - 't': ptrdiff_t
#
# Allowed conversions:
# - u: unsigned decimal integer
udecint_re = re.compile(
    "%([0\\-]*)([0-9]*|[*])((\\.[0-9]*|\\.[*])?)(hh|h|l|ll|q|z|Z|j|t|)(u)"
)

# Unsigned non-decimal int conversion
#
# Allowed flags:
# - '#': Add '0o' or '0x' prefix, as appropriate
# - '0': Justify the field with zeros
# - '-': Left-justify the field.  Default is right-justify
#
# Allowed lengths:
# - 'hh': char
# - 'h': short
# - '': int
# - 'l': long
# - 'll', 'q': long long
# - 'z', 'Z': size_t
# - 'j': intmax_t
# - 't': ptrdiff_t
#
# Allowed conversions:
# - o: unsigned octal integer
# - x: unsigned hexadecimal integer, lowercase
# - X: unsigned hexadecimal integer, uppercase
uint_re = re.compile(
    "%([#0\\-]*)([0-9]*|[*])((\\.[0-9]*|\\.[*])?)(hh|h|l|ll|q|z|Z|j|t|)(o|x|X)"
)

# Scientific notation conversion
#
# D.DDeDD
#
# Allowed flags:
# - '#': Include decimal and fractional component if zero
# - '0': Justify the field with zeros
# - ' ': Add a space before a positive number
# - '-': Left-justify the field.  Default is right-justify
# - '+': Always include a sign symbol
#
# Allowed lengths
# - '': double (the compiler better damned well have gotten this right).
# - 'L': long double
#
# Allowed conversions:
# - 'e': Scientific notation, lowercase
# - 'E': Scientific notation, uppercase
sci_re = re.compile("%([#0 \\-+]*)([0-9]*|[*])((\\.[0-9]*|\\.[*])?)(L|)(e|E)")

# Floating point conversion
#
# DD.DD
#
# Allowed flags:
# - '#': Include decimal and fractional component if zero
# - '0': Justify the field with zeros
# - ' ': Add a space before a positive number
# - '-': Left-justify the field.  Default is right-justify
# - '+': Always include a sign symbol
#
# Allowed lengths
# - '': double (the compiler better damned well have gotten this right).
# - 'L': long double
#
# Allowed conversions:
# - 'e': Floating-point, lowercase
# - 'E': Floating-point, uppercase
float_re = re.compile("%([#0 \\-+]*)([0-9]*|[*])((\\.[0-9]*|\\.[*])?)(L|)(f|F)")

# Size-sensitive floating point conversion
#
# DD.DD or D.DDeDD, depending on magnitude
#
# Allowed flags:
# - '#': Include decimal and fractional component if zero
# - '0': Justify the field with zeros
# - ' ': Add a space before a positive number
# - '-': Left-justify the field.  Default is right-justify
# - '+': Always include a sign symbol
#
# Allowed lengths
# - '': double (the compiler better damned well have gotten this right).
# - 'L': long double
#
# Allowed conversions:
# - 'g': Floating-point, lowercase
# - 'G': Floating-point, uppercase
scifloat_re = re.compile("%([#0 \\-+]*)([0-9]*|[*])((\\.[0-9]*|\\.[*])?)(L|)(g|G)")

# Hexadecimal floating point conversion
#
# 0xXX.XX
#
# Allowed flags:
# - '#': Include decimal and fractional component if zero
# - '0': Justify the field with zeros
# - ' ': Add a space before a positive number
# - '-': Left-justify the field.  Default is right-justify
# - '+': Always include a sign symbol
#
# Allowed lengths
# - '': double (the compiler better damned well have gotten this right).
# - 'L': long double
#
# Allowed conversions:
# - 'a': Hexadecimal floating-point, lowercase
# - 'A': Hexadecimal floating-point, uppercase
hexfloat_re = re.compile("%([#0 \\-+]*)([0-9]*|[*])((\\.[0-9]+|\\.[*])?)(L|)(g|G)")

# Character conversion
#
# c
#
# Allowed flags:
# - ' ': Add a space before a string
# - '-': Left-justify the field.  Default is right-justify
#
# Allowed Lengths:
# - ' ': unsigned char
# - 'l': wchar_t
#
# Allowed conversions:
# - 'c': Character
char_re = re.compile("%([ \\-]*)([0-9]*|[*])()()(l|)(c)")

# String conversion
#
# cccccccc
#
# Allowed flags:
# - ' ': Add a space before a string
# - '-': Left-justify the field.  Default is right-justify
#
# Allowed lengths
# - '': char *
# - 'l': wchar_t *
#
# Allowed conversions:
# - s: String
str_re = re.compile("%([ \\-]*)([0-9]*|[*])((\\.[0-9]+|\\.[*])?)(l|)(s)")

# Pointer conversion
#
# 0xXXXXXXXX
#
# Allowed flags:
# - '-': Left-justify the field.
#
# Allowed lengths:
# - '': void *
#
# Allowed conversions:
# - p: pointer
pointer_re = re.compile("%([\\-]?)([0-9]*|[*])()()()(p)")

# Length of current output
#
# <prints nothing>
#
# Allowed flags:
# - None
#
# Allowed lengths:
# - 'hh': char *
# - 'h': short *
# - '': int *
# - 'l': long *
# - 'll', 'q': long long *
# - 'z', 'Z': size_t *
# - 'j': intmax_t *
# - 't': ptrdiff_t *
#
# Allowed conversions:
# - 'n': Fetch length of current output
len_re = re.compile("%()()()()(hh|h|l|ll|q|z|Z|j|t|)(n)")

# Strerror conversion
#
# ssssssss # result of strerror(errno)
#
# Allowed flags:
# - ' ': Add a space before a string
# - '-': Left-justify the field.  Default is right-justify
#
# Allowed lengths:
# - '': Default; this doesn't take an argument.
#
# Allowed conversions:
# - varargs: VariadicContext, m: strerror
strerror_re = re.compile("%([ \\-]*)([0-9]*|[*])()()()(m)")

# Percent sign
#
# %
#
# Allowed flags:
# - None
#
# Allowed lengths:
# - None
#
# Allowed conversions:
# - '%': Print a literal '%'
percent_re = re.compile("%%")


class FormatConversionError(Exception):
    pass


def handle_flags(flags: str) -> str:
    out = ""
    if "-" in flags:
        out += "<"
    else:
        out += ">"

    if "+" in flags:
        out += "+"

    if " " in flags:
        out += " "

    if "0" in flags:
        out += "0"

    if "#" in flags:
        out += "#"

    return out


def handle_width(width: str, varargs: VariadicContext, emulator: Emulator) -> str:
    if width == "*":
        width_int = varargs.get_next_argument(ArgumentType.INT, emulator)
        assert isinstance(width_int, int)
        return str(width_int)
    else:
        return width


def handle_precision(
    precision: str, varargs: VariadicContext, emulator: Emulator, use_default=True
) -> str:
    if precision == ".*":
        precision_int = varargs.get_next_argument(ArgumentType.INT, emulator)
        assert isinstance(precision_int, int)
        return "." + str(precision_int)
    elif precision == ".":
        return ".0"
    elif precision == "":
        if use_default:
            return ".6"
        else:
            return ""
    else:
        return precision


def handle_double_arg(
    length: str, varargs: VariadicContext, emulator: Emulator
) -> float:
    if length == "":
        val = varargs.get_next_argument(ArgumentType.DOUBLE, emulator)
    elif length == "L":
        raise NotImplementedError("Type 'long double' not handled")
    else:
        raise FormatConversionError(f"Unknown type specifier {length}")
    assert isinstance(val, float)
    return val


def handle_sdecint(
    output: str, varargs: VariadicContext, m: re.Match, emulator: Emulator
) -> str:
    flags = m.group(1)
    width = m.group(2)
    precision = m.group(3)
    length = m.group(5)
    # Conversion is irrelevant; they're aliases for the same thing.

    fmt = "{:"

    # Handle flags
    # These mean the same for python as they do for C,
    # with the exception of '-' in C being '<' in Python
    flags = handle_flags(flags)
    fmt += flags

    # Handle width
    width = handle_width(width, varargs, emulator)
    fmt += width

    # Handle precision
    # Precision in ints acts like a second width,
    # which always has the '0' flag enabled.
    # This isn't implemented in python, which means we need to do it piecewise
    if precision != "":
        raise NotImplementedError("TODO: Implemente precision for ints")

    # Handle length
    if length in ("hh", "h", ""):
        # Variadics don't go smaller than 'int'
        val = varargs.get_next_argument(ArgumentType.INT, emulator)
    elif length == "l":
        val = varargs.get_next_argument(ArgumentType.LONG, emulator)
    elif length in ("ll", "q"):
        val = varargs.get_next_argument(ArgumentType.LONGLONG, emulator)
    elif length in ("z", "Z"):
        val = varargs.get_next_argument(ArgumentType.SSIZE_T, emulator)
    elif length == "j":
        raise NotImplementedError("Type 'intmax_t' not handled")
    elif length == "t":
        raise NotImplementedError("Type 'ptrdiff_t' not handled")
    else:
        raise FormatConversionError(f"Unknown type specifier {length}")

    assert isinstance(val, int)

    fmt += "d}"

    return fmt.format(val)


def handle_udecint(
    output: str, varargs: VariadicContext, m: re.Match, emulator: Emulator
) -> str:
    flags = m.group(1)
    width = m.group(2)
    precision = m.group(3)
    length = m.group(5)
    # Conversion is irrelevant; they're aliases for the same thing.

    fmt = "{:"

    # Handle flags
    # These mean the same for python as they do for C,
    # with the exception of '-' in C being '<' in Python
    flags = handle_flags(flags)
    fmt += flags

    # Handle width
    width = handle_width(width, varargs, emulator)
    fmt += width

    # Handle precision
    # Precision in ints acts like a second width,
    # which always has the '0' flag enabled.
    # This isn't implemented in python, which means we need to do it piecewise
    if precision != "":
        raise NotImplementedError("TODO: Implemente precision for ints")

    # Handle length
    if length in ("hh", "h", ""):
        # Variadics don't go smaller than 'int'
        val = varargs.get_next_argument(ArgumentType.UINT, emulator)
    elif length == "l":
        val = varargs.get_next_argument(ArgumentType.ULONG, emulator)
    elif length in ("ll", "q"):
        val = varargs.get_next_argument(ArgumentType.ULONGLONG, emulator)
    elif length in ("z", "Z"):
        val = varargs.get_next_argument(ArgumentType.SIZE_T, emulator)
    elif length == "j":
        raise NotImplementedError("Type 'intmax_t' not handled")
    elif length == "t":
        raise NotImplementedError("Type 'ptrdiff_t' not handled")
    else:
        raise FormatConversionError(f"Unknown type specifier {length}")
    assert isinstance(val, int)

    fmt += "d}"

    return fmt.format(val)


def handle_uint(
    output: str, varargs: VariadicContext, m: re.Match, emulator: Emulator
) -> str:
    flags = m.group(1)
    width = m.group(2)
    precision = m.group(3)
    length = m.group(5)
    conv = m.group(6)

    # Handle flags
    # These mean the same for python as they do for C,
    # with the exception of '-' in C being '<' in Python
    flags = handle_flags(flags)
    # In C, octals can have both '#' and '0' flags.
    # In practice, the '#' is redundant, and forbidden by Python
    if "0" in flags:
        flags = flags.replace("#", "")

    # Handle width
    width = handle_width(width, varargs, emulator)

    # Handle precision
    # Precision in ints acts like a second width,
    # which always has the '0' flag enabled.
    # This isn't implemented in python, which means we need to do it piecewise
    if precision != "":
        raise NotImplementedError("TODO: Implemente precision for ints")

    # Handle length
    if length in ("hh", "h", ""):
        # Variadics don't go smaller than 'int'
        val = varargs.get_next_argument(ArgumentType.UINT, emulator)
    elif length == "l":
        val = varargs.get_next_argument(ArgumentType.ULONG, emulator)
    elif length in ("ll", "q"):
        val = varargs.get_next_argument(ArgumentType.ULONGLONG, emulator)
    elif length in ("z", "Z"):
        val = varargs.get_next_argument(ArgumentType.SIZE_T, emulator)
    elif length == "j":
        raise NotImplementedError("Type 'intmax_t' not handled")
    elif length == "t":
        raise NotImplementedError("Type 'ptrdiff_t' not handled")
    else:
        raise FormatConversionError(f"Unknown type specifier {length}")

    assert isinstance(val, int)

    fmt = "{:"
    fmt += flags
    fmt += width
    fmt += conv
    fmt += "}"
    res = fmt.format(val)
    if "#" in flags and conv == "o":
        if width != "":
            int_width = int(width)
        else:
            int_width = 0
        extend = len(res) == int_width
        res = res.replace("0o", "0")
        if extend:
            res = " " + res

    return res


def handle_sci(
    output: str, varargs: VariadicContext, m: re.Match, emulator: Emulator
) -> str:
    flags = m.group(1)
    width = m.group(2)
    precision = m.group(3)
    length = m.group(5)
    conv = m.group(6)

    fmt = "{:"

    # Handle flags
    # These mean the same for python as they do for C,
    # with the exception of '-' in C being '<' in Python
    flags = handle_flags(flags)
    fmt += flags

    # Handle width
    width = handle_width(width, varargs, emulator)
    fmt += width

    # Handle precision
    precision = handle_precision(precision, varargs, emulator)
    fmt += precision

    # Handle length
    val = handle_double_arg(length, varargs, emulator)

    fmt += conv
    fmt += "}"

    out = fmt.format(val)

    # Handle negative NaN.
    # Python prints it as positive NaN.
    byteval = struct.pack("<d", val)
    intval = int.from_bytes(byteval, "little")
    if intval == 0xFFF8000000000000:
        text = ("{:" + conv + "}").format(val)
        index = out.index(text)
        if index == 0:
            out = out.replace(text, "-" + text)
        else:
            out = out[: index - 1] + "-" + text + out[index + 3 :]

    return out


def handle_float(
    output: str, varargs: VariadicContext, m: re.Match, emulator: Emulator
) -> str:
    flags = m.group(1)
    width = m.group(2)
    precision = m.group(3)
    length = m.group(5)
    conv = m.group(6)

    fmt = "{:"

    # Handle flags
    # These mean the same for python as they do for C,
    # with the exception of '-' in C being '<' in Python
    flags = handle_flags(flags)
    fmt += flags

    # Handle width
    width = handle_width(width, varargs, emulator)
    fmt += width

    # Handle precision
    precision = handle_precision(precision, varargs, emulator)
    fmt += precision

    # Handle length
    val = handle_double_arg(length, varargs, emulator)

    fmt += conv
    fmt += "}"

    out = fmt.format(val)

    # Handle negative NaN.
    # Python prints it as positive NaN.
    byteval = struct.pack("<d", val)
    intval = int.from_bytes(byteval, "little")
    if intval == 0xFFF8000000000000:
        text = ("{:" + conv + "}").format(val)
        index = out.index(text)
        if index == 0:
            out = out.replace(text, "-" + text)
        else:
            out = out[: index - 1] + "-" + text + out[index + 3 :]

    return out


def handle_scifloat(
    output: str, varargs: VariadicContext, m: re.Match, emulator: Emulator
) -> str:
    flags = m.group(1)
    width = m.group(2)
    precision = m.group(3)
    length = m.group(5)
    conv = m.group(6)

    fmt = "{:"

    # Handle flags
    # These mean the same for python as they do for C,
    # with the exception of '-' in C being '<' in Python
    flags = handle_flags(flags)
    fmt += flags

    # Handle width
    width = handle_width(width, varargs, emulator)
    fmt += width

    # Handle precision
    precision = handle_precision(precision, varargs, emulator)
    fmt += precision

    # Handle length
    val = handle_double_arg(length, varargs, emulator)

    fmt += conv
    fmt += "}"

    out = fmt.format(val)

    # Handle negative NaN.
    # Python prints it as positive NaN.
    byteval = struct.pack("<d", val)
    intval = int.from_bytes(byteval, "little")

    if intval == 0xFFF8000000000000:
        text = ("{:" + conv + "}").format(val)
        index = out.index(text)
        if index == 0:
            out = out.replace(text, "-" + text)
        else:
            out = out[: index - 1] + "-" + text + out[index + 3 :]

    return out


def handle_hexfloat(
    output: str, varargs: VariadicContext, m: re.Match, emulator: Emulator
) -> str:
    # Python doesn't have an easy conversion for hex floats
    # And I am not writing one unless you absolutely need it.
    raise NotImplementedError("Hexadecimal float conversion not supported")


def handle_char(
    output: str, varargs: VariadicContext, m: re.Match, emulator: Emulator
) -> str:
    flags = m.group(1)
    width = m.group(2)
    length = m.group(5)
    conv = m.group(6)

    fmt = "{:"

    # Handle flags
    # These mean the same for python as they do for C,
    # with the exception of '-' in C being '<' in Python
    flags = handle_flags(flags)

    # Handle width
    width = handle_width(width, varargs, emulator)
    fmt += width

    # Handle length
    if length == "":
        val = varargs.get_next_argument(ArgumentType.UINT, emulator)
    elif length == "l":
        raise NotImplementedError("Type 'wchar_t' not handled")
    else:
        raise FormatConversionError(f"Unknown type specifier {length}")

    assert isinstance(val, int)
    val = val & 0xFF

    fmt += conv
    fmt += "}"

    return fmt.format(val)


def handle_str(
    output: str, varargs: VariadicContext, m: re.Match, emulator: Emulator
) -> str:
    flags = m.group(1)
    width = m.group(2)
    precision = m.group(3)
    length = m.group(5)
    conv = m.group(6)

    fmt = "{:"

    # Handle flags
    # These mean the same for python as they do for C,
    # with the exception of '-' in C being '<' in Python
    flags = handle_flags(flags)
    fmt += flags

    # Handle width
    width = handle_width(width, varargs, emulator)
    fmt += width

    # Handle precision
    # Highly fortunately, this works the same in python
    precision = handle_precision(precision, varargs, emulator, use_default=False)
    fmt += precision

    # Handle length
    if length == "":
        addr = varargs.get_next_argument(ArgumentType.POINTER, emulator)
    elif length == "l":
        raise NotImplementedError("Type 'wchar_t *' not handled")
    else:
        raise FormatConversionError(f"Unknown type specifier {length}")

    assert isinstance(addr, int)

    val_len = _emu_strlen(emulator, addr)
    val_bytes = emulator.read_memory(addr, val_len)
    val = val_bytes.decode("utf-8")

    fmt += conv
    fmt += "}"

    return fmt.format(val)


def handle_pointer(
    output: str, varargs: VariadicContext, m: re.Match, emulator: Emulator
) -> str:
    flags = m.group(1)
    width = m.group(2)

    fmt = "{:"

    # Handle flags
    # These mean the same for python as they do for C,
    # with the exception of '-' in C being '<' in Python
    flags = handle_flags(flags)
    fmt += flags + "#"

    # Handle width
    width = handle_width(width, varargs, emulator)
    fmt += width

    val = varargs.get_next_argument(ArgumentType.POINTER, emulator)
    assert isinstance(val, int)

    fmt += "x}"

    return fmt.format(val)


def handle_len(
    output: str, varargs: VariadicContext, m: re.Match, emulator: Emulator
) -> str:
    length = m.group(5)

    addr = varargs.get_next_argument(ArgumentType.POINTER, emulator)
    assert isinstance(addr, int)

    val = len(output)
    if length == "hh":
        val = val & 0xFF
        width = 1
    elif length == "h":
        val = val & 0xFFFF
        width = 2
    elif length == "":
        val = val & varargs._int_inv_mask
        width = 4
    elif length in ("l", "z", "Z"):
        val = val & varargs._long_inv_mask
        width = 4 if ArgumentType.LONG in varargs._four_byte_types else 8
    elif length in ("ll", "q"):
        val = val & varargs._long_long_inv_mask
        width = 8
    elif length == "j":
        raise NotImplementedError("Type 'intmax_t' not handled")
    elif length == "t":
        raise NotImplementedError("Type 'ptrdiff_t' not handled")
    else:
        raise FormatConversionError(f"Unknown type specifier {length}")

    if varargs.platform.byteorder == Byteorder.LITTLE:
        data = val.to_bytes(width, "little")
    else:
        data = val.to_bytes(width, "big")

    emulator.write_memory(addr, data)

    return ""


def handle_strerror(
    output: str, varargs: VariadicContext, m: re.Match, emulator: Emulator
) -> str:
    # This depends on the actual errno global,
    # to which I do not have access.
    raise NotImplementedError("Strerror conversion not supported")


def handle_percent(
    output: str, varargs: VariadicContext, m: re.Match, emulator: Emulator
) -> str:
    # If this has any configurable options, I will be most displeased.
    return "%"


def parse_printf_format(model: CStdModel, fmt: str, emulator: Emulator) -> str:
    handlers: typing.List[
        typing.Tuple[
            re.Pattern, typing.Callable[[str, VariadicContext, re.Match, Emulator], str]
        ]
    ] = [
        (sdecint_re, handle_sdecint),
        (udecint_re, handle_udecint),
        (uint_re, handle_uint),
        (sci_re, handle_sci),
        (float_re, handle_float),
        (scifloat_re, handle_scifloat),
        (hexfloat_re, handle_hexfloat),
        (char_re, handle_char),
        (str_re, handle_str),
        (pointer_re, handle_pointer),
        (len_re, handle_len),
        (strerror_re, handle_strerror),
        (percent_re, handle_percent),
    ]

    varargs = model.get_varargs()

    orig_fmt = fmt
    output = ""

    while len(fmt) > 0:
        if fmt.startswith("%"):
            matched = False
            for regex, handler in handlers:
                if isinstance(regex, str):
                    raise Exception(f"String: {regex}")
                m = regex.match(fmt)
                if m is not None:
                    try:
                        output += handler(output, varargs, m, emulator)
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

        else:
            output += fmt[0]
            fmt = fmt[1:]

    return output
