import locale

from .... import emulators, exceptions
from ..cstd import ArgumentType, CStdModel
from .utils import (
    MAX_STRLEN,
    _emu_memcmp,
    _emu_memcpy,
    _emu_strlen,
    _emu_strncat,
    _emu_strncmp,
    _emu_strnlen,
)


class Memcpy(CStdModel):
    name = "memcpy"

    # void *memcpy(void *restrict dst, const void *restrict src, size_t n);
    argument_types = [ArgumentType.POINTER, ArgumentType.POINTER, ArgumentType.SIZE_T]
    return_type = ArgumentType.POINTER

    def model(self, emulator: emulators.Emulator) -> None:
        dst = self.get_arg1(emulator)
        src = self.get_arg2(emulator)
        n = self.get_arg3(emulator)

        assert isinstance(dst, int)
        assert isinstance(src, int)
        assert isinstance(n, int)

        # FIXME: Does not actually mimic memcpy
        # Will not clobber overlapping buffers
        _emu_memcpy(emulator, dst, src, n)
        self.set_return_value(emulator, dst)


class Memmove(CStdModel):
    name = "memmove"

    # void *memmove(void *restrict dst, const void *restrict src, size_t n);
    argument_types = [ArgumentType.POINTER, ArgumentType.POINTER, ArgumentType.SIZE_T]
    return_type = ArgumentType.POINTER

    def model(self, emulator: emulators.Emulator) -> None:
        dst = self.get_arg1(emulator)
        src = self.get_arg2(emulator)
        n = self.get_arg3(emulator)

        assert isinstance(dst, int)
        assert isinstance(src, int)
        assert isinstance(n, int)

        _emu_memcpy(emulator, dst, src, n)
        self.set_return_value(emulator, dst)


class Strcat(CStdModel):
    name = "strcat"

    # char *strcat(char *restrict s1, const char *restrict s2);
    argument_types = [ArgumentType.POINTER, ArgumentType.POINTER]
    return_type = ArgumentType.POINTER

    def model(self, emulator: emulators.Emulator) -> None:
        dst = self.get_arg1(emulator)
        src = self.get_arg2(emulator)

        assert isinstance(dst, int)
        assert isinstance(src, int)

        _emu_strncat(emulator, dst, src, MAX_STRLEN)
        self.set_return_value(emulator, dst)


class Strncat(CStdModel):
    name = "strncat"

    # char *strncat(char *restrict s1, const char *restrict s2, size_t n);
    argument_types = [ArgumentType.POINTER, ArgumentType.POINTER, ArgumentType.SIZE_T]
    return_type = ArgumentType.POINTER

    def model(self, emulator: emulators.Emulator) -> None:
        dst = self.get_arg1(emulator)
        src = self.get_arg2(emulator)
        n = self.get_arg3(emulator)

        assert isinstance(dst, int)
        assert isinstance(src, int)
        assert isinstance(n, int)

        _emu_strncat(emulator, dst, src, n)
        self.set_return_value(emulator, dst)


class Memcmp(CStdModel):
    name = "memcmp"

    # int memcmp(const void *ptr1, const void *ptr2, size_t n);
    argument_types = [ArgumentType.POINTER, ArgumentType.POINTER, ArgumentType.SIZE_T]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        ptr1 = self.get_arg1(emulator)
        ptr2 = self.get_arg2(emulator)
        n = self.get_arg3(emulator)

        assert isinstance(ptr1, int)
        assert isinstance(ptr2, int)
        assert isinstance(n, int)

        res = _emu_memcmp(emulator, ptr1, ptr2, n)
        self.set_return_value(emulator, res)


class Strncmp(CStdModel):
    name = "strncmp"

    # int strncmp(const void *ptr1, const void *ptr2, size_t n);
    argument_types = [ArgumentType.POINTER, ArgumentType.POINTER, ArgumentType.SIZE_T]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        # int strncmp(const char *ptr1, const char *ptr2, size_t n);
        ptr1 = self.get_arg1(emulator)
        ptr2 = self.get_arg2(emulator)
        n = self.get_arg3(emulator)

        assert isinstance(ptr1, int)
        assert isinstance(ptr2, int)
        assert isinstance(n, int)

        res = _emu_strncmp(emulator, ptr1, ptr2, n)
        self.set_return_value(emulator, res)


class Strcmp(CStdModel):
    name = "strcmp"

    # int strcmp(const void *ptr1, const void *ptr2);
    argument_types = [ArgumentType.POINTER, ArgumentType.POINTER]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        # int strcmp(const char *ptr1, const char *ptr2);
        ptr1 = self.get_arg1(emulator)
        ptr2 = self.get_arg2(emulator)

        assert isinstance(ptr1, int)
        assert isinstance(ptr2, int)

        res = _emu_strncmp(emulator, ptr1, ptr2, MAX_STRLEN)
        self.set_return_value(emulator, res)


class Strcoll(CStdModel):
    name = "strcoll"

    # int strcoll(const void *ptr1, const void *ptr2);
    argument_types = [ArgumentType.POINTER, ArgumentType.POINTER]
    return_type = ArgumentType.INT

    def __init__(self, address: int):
        super().__init__(address)
        # NOTE: This requries extra configuration; set `locale` to the preferred locale.
        # TODO: Think of a way to support dynamically-changing locales.
        self.locale = ""

    def model(self, emulator: emulators.Emulator) -> None:
        ptr1 = self.get_arg1(emulator)
        ptr2 = self.get_arg2(emulator)

        assert isinstance(ptr1, int)
        assert isinstance(ptr2, int)

        # TODO: This might be wrong if CTYPE is different
        len1 = _emu_strlen(emulator, ptr1)
        len2 = _emu_strlen(emulator, ptr2)

        bytes1 = emulator.read_memory(ptr1, len1)
        bytes2 = emulator.read_memory(ptr2, len2)

        try:
            # Risky.  Inside this section, the locale will be different.
            old_locale = locale.getlocale(category=locale.LC_COLLATE)
            locale.setlocale(locale.LC_COLLATE, self.locale)
            locale.setlocale(locale.LC_CTYPE, self.locale)

            encoding = locale.getpreferredencoding()

            str1 = bytes1.decode(encoding)
            str2 = bytes2.decode(encoding)

            res = locale.strcoll(str1, str2)

            locale.setlocale(locale.LC_COLLATE, old_locale)
            locale.setlocale(locale.LC_CTYPE, old_locale)
        except Exception as e:
            locale.setlocale(locale.LC_COLLATE, old_locale)
            locale.setlocale(locale.LC_CTYPE, old_locale)
            raise e

        self.set_return_value(emulator, res)


class Strxfrm(CStdModel):
    name = "strxfrm"

    # size_t strxfrm(char *dst, const char *src, size_t n);
    argument_types = [ArgumentType.POINTER, ArgumentType.POINTER, ArgumentType.SIZE_T]
    return_type = ArgumentType.SIZE_T

    def __init__(self, address: int):
        super().__init__(address)
        # NOTE: This requries extra configuration; set `locale` to the preferred locale.
        # TODO: Think of a way to support dynamically-changing locales.
        self.locale = ""

    def model(self, emulator: emulators.Emulator) -> None:
        dst = self.get_arg1(emulator)
        src = self.get_arg2(emulator)
        n = self.get_arg3(emulator)

        assert isinstance(dst, int)
        assert isinstance(src, int)
        assert isinstance(n, int)

        # TODO: This might be wrong if CTYPE is different
        if n == 0:
            n = _emu_strlen(emulator, src)
        else:
            n = _emu_strnlen(emulator, src, n)

        self.set_return_value(emulator, n)

        if dst == 0:
            return

        bytes1 = emulator.read_memory(src, n)

        try:
            # Risky.  Inside this section, the locale will be different.
            old_locale = locale.getlocale(category=locale.LC_COLLATE)
            locale.setlocale(locale.LC_COLLATE, self.locale)
            locale.setlocale(locale.LC_CTYPE, self.locale)

            encoding = locale.getpreferredencoding()

            str1 = bytes1.decode(encoding)

            str2 = locale.strxfrm(str1)

            bytes2 = str2.encode(encoding)

            locale.setlocale(locale.LC_COLLATE, old_locale)
            locale.setlocale(locale.LC_CTYPE, old_locale)
        except Exception as e:
            locale.setlocale(locale.LC_COLLATE, old_locale)
            locale.setlocale(locale.LC_CTYPE, old_locale)
            raise e

        emulator.write_memory(dst, bytes2)


class Memchr(CStdModel):
    name = "memchr"

    # const void *memchr(const void *ptr, int value, size_t n);
    argument_types = [ArgumentType.POINTER, ArgumentType.INT, ArgumentType.SIZE_T]
    return_type = ArgumentType.SIZE_T

    def model(self, emulator: emulators.Emulator) -> None:
        # const void *memchr(const void *ptr, int value, size_t n);
        ptr = self.get_arg1(emulator)
        val = self.get_arg2(emulator)
        n = self.get_arg3(emulator)

        assert isinstance(ptr, int)
        assert isinstance(val, int)
        assert isinstance(n, int)

        data = emulator.read_memory(ptr, n)
        for i in range(0, n):
            if data[i] == val:
                self.set_return_value(emulator, ptr + i)
                return

        self.set_return_value(emulator, 0)


class Strchr(CStdModel):
    name = "strchr"

    # const char *strchr(const char *ptr, int value);
    argument_types = [ArgumentType.POINTER, ArgumentType.INT]
    return_type = ArgumentType.POINTER

    def model(self, emulator: emulators.Emulator) -> None:
        ptr = self.get_arg1(emulator)
        val = self.get_arg2(emulator)

        assert isinstance(ptr, int)
        assert isinstance(val, int)

        n = _emu_strlen(emulator, ptr)

        data = emulator.read_memory(ptr, n)
        for i in range(0, n):
            if data[i] == val:
                self.set_return_value(emulator, ptr + i)
                return

        self.set_return_value(emulator, 0)


class Strcspn(CStdModel):
    name = "strcspn"

    # size_t strcspn(const char *str1, const char *str2);
    argument_types = [ArgumentType.POINTER, ArgumentType.POINTER]
    return_type = ArgumentType.SIZE_T

    def model(self, emulator: emulators.Emulator) -> None:
        # size_t strcspn(const char *str1, const char *str2);
        ptr1 = self.get_arg1(emulator)
        ptr2 = self.get_arg2(emulator)

        assert isinstance(ptr1, int)
        assert isinstance(ptr2, int)

        len1 = _emu_strlen(emulator, ptr1)
        len2 = _emu_strlen(emulator, ptr2)

        bytes1 = emulator.read_memory(ptr1, len1)
        bytes2 = emulator.read_memory(ptr2, len2)

        needles = {x for x in bytes2}

        for i in range(0, len1):
            if bytes1[i] in needles:
                self.set_return_value(emulator, i)
                return

        self.set_return_value(emulator, len1)


class Strpbrk(CStdModel):
    name = "strpbrk"

    # const char *strpbrk(const char *str1, const char *str2);
    argument_types = [ArgumentType.POINTER, ArgumentType.POINTER]
    return_type = ArgumentType.POINTER

    def model(self, emulator: emulators.Emulator) -> None:
        ptr1 = self.get_arg1(emulator)
        ptr2 = self.get_arg2(emulator)

        assert isinstance(ptr1, int)
        assert isinstance(ptr2, int)

        len1 = _emu_strlen(emulator, ptr1)
        len2 = _emu_strlen(emulator, ptr2)

        bytes1 = emulator.read_memory(ptr1, len1)
        bytes2 = emulator.read_memory(ptr2, len2)

        needles = {x for x in bytes2}

        for i in range(0, len1):
            if bytes1[i] in needles:
                self.set_return_value(emulator, ptr1 + i)
                return

        self.set_return_value(emulator, 0)


class Strrchr(CStdModel):
    name = "strrchr"

    # const char *strrchr(const char *ptr, int value);
    argument_types = [ArgumentType.POINTER, ArgumentType.INT]
    return_type = ArgumentType.POINTER

    def model(self, emulator: emulators.Emulator) -> None:
        ptr = self.get_arg1(emulator)
        val = self.get_arg2(emulator)

        assert isinstance(ptr, int)
        assert isinstance(val, int)

        n = _emu_strlen(emulator, ptr)

        data = emulator.read_memory(ptr, n)

        for i in range(n - 1, -1, -1):
            if data[i] == val:
                self.set_return_value(emulator, ptr + i)
                return

        self.set_return_value(emulator, 0)


class Strspn(CStdModel):
    name = "strspn"

    # size_t strspn(const char *str1, const char *str2);
    argument_types = [ArgumentType.POINTER, ArgumentType.POINTER]
    return_type = ArgumentType.SIZE_T

    def model(self, emulator: emulators.Emulator) -> None:
        ptr1 = self.get_arg1(emulator)
        ptr2 = self.get_arg2(emulator)

        assert isinstance(ptr1, int)
        assert isinstance(ptr2, int)

        len1 = _emu_strlen(emulator, ptr1)
        len2 = _emu_strlen(emulator, ptr2)

        bytes1 = emulator.read_memory(ptr1, len1)
        bytes2 = emulator.read_memory(ptr2, len2)

        needles = {x for x in bytes2}

        for i in range(0, len1):
            if bytes1[i] not in needles:
                self.set_return_value(emulator, i)
                return

        self.set_return_value(emulator, len1)


class Strstr(CStdModel):
    name = "strstr"

    # const char *strstr(const char *str1, const char *str2);
    argument_types = [ArgumentType.POINTER, ArgumentType.POINTER]
    return_type = ArgumentType.POINTER

    def model(self, emulator: emulators.Emulator) -> None:
        ptr1 = self.get_arg1(emulator)
        ptr2 = self.get_arg2(emulator)

        assert isinstance(ptr1, int)
        assert isinstance(ptr2, int)

        len1 = _emu_strlen(emulator, ptr1)
        len2 = _emu_strlen(emulator, ptr2)

        bytes1 = emulator.read_memory(ptr1, len1)
        bytes2 = emulator.read_memory(ptr2, len2)

        for i in range(0, len1):
            if bytes1[i : i + len2] == bytes2:
                self.set_return_value(emulator, ptr1 + i)
                return

        self.set_return_value(emulator, 0)


class Strtok(CStdModel):
    name = "strtok"

    # char *strtok(char *str, const char *delimiters);
    argument_types = [ArgumentType.POINTER, ArgumentType.POINTER]
    return_type = ArgumentType.POINTER

    def __init__(self, address: int):
        super().__init__(address)
        self.ptr = 0

    def model(self, emulator: emulators.Emulator) -> None:
        ptr1 = self.get_arg1(emulator)
        ptr2 = self.get_arg2(emulator)

        assert isinstance(ptr1, int)
        assert isinstance(ptr2, int)

        if ptr1 == 0:
            if self.ptr == 0:
                raise exceptions.EmulationError(
                    "strtok called with NULL when placeholder was NULL"
                )

        len1 = _emu_strlen(emulator, ptr1)
        len2 = _emu_strlen(emulator, ptr2)

        bytes1 = emulator.read_memory(ptr1, len1)
        bytes2 = emulator.read_memory(ptr2, len2)

        if len1 == 0:
            # Empty string; we're out of tokens.
            self.set_return_value(emulator, 0)
            return

        # Non-empty string; we will have a token.
        self.set_return_value(emulator, ptr1)

        needles = {x for x in bytes2}
        for i in range(0, len1):
            if bytes1[i] in needles:
                emulator.write_memory(ptr1 + i, b"\0")
                self.ptr = ptr1 + i + 1
            if bytes1[i] == 0:
                self.ptr = 0


class Memset(CStdModel):
    name = "memset"

    # void *memset(void *ptr, int value, size_t num);
    argument_types = [ArgumentType.POINTER, ArgumentType.INT, ArgumentType.SIZE_T]
    return_type = ArgumentType.POINTER

    def model(self, emulator: emulators.Emulator) -> None:
        ptr = self.get_arg1(emulator)
        val = self.get_arg2(emulator)
        n = self.get_arg3(emulator)

        assert isinstance(ptr, int)
        assert isinstance(val, int)
        assert isinstance(n, int)

        data = bytes([val & 0xFF]) * n
        emulator.write_memory(ptr, data)

        self.set_return_value(emulator, ptr)


class Strerror(CStdModel):
    name = "strerror"

    # const char *strerror(int errno);
    argument_types = [ArgumentType.INT]
    return_type = ArgumentType.POINTER

    def model(self, emulator: emulators.Emulator) -> None:
        # TODO: Figure out strerror
        # This devolves into a titanic, platform-specific table lookup.
        # The biggest problem is the platform-specific bit;
        # it goes beyond ISA/ABI and into OS version.
        raise NotImplementedError()


class Strlen(CStdModel):
    name = "strlen"

    # size_t strlen(const char *str);
    argument_types = [ArgumentType.POINTER]
    return_type = ArgumentType.SIZE_T

    def model(self, emulator: emulators.Emulator) -> None:
        ptr = self.get_arg1(emulator)

        assert isinstance(ptr, int)

        res = _emu_strlen(emulator, ptr)
        self.set_return_value(emulator, res)


__all__ = [
    "Memcpy",
    "Memmove",
    "Strcat",
    "Strncat",
    "Memcmp",
    "Strncmp",
    "Strcmp",
    "Strcoll",
    "Strxfrm",
    "Memchr",
    "Strchr",
    "Strcspn",
    "Strpbrk",
    "Strrchr",
    "Strspn",
    "Strstr",
    "Strtok",
    "Memset",
    "Strerror",
    "Strlen",
]
