import locale

from .... import emulators, exceptions
from ..cstd import CStdModel
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

    def model(self, emulator: emulators.Emulator) -> None:
        # void *memcpy(void *restrict dst, const void *restrict src, size_t n);
        dst = self.get_arg1(emulator)
        src = self.get_arg2(emulator)
        n = self.get_arg3(emulator)
        # FIXME: Does not actually mimic memcpy
        # Will not clobber overlapping buffers
        _emu_memcpy(emulator, dst, src, n)
        self.set_return_value(emulator, dst)


class Memmove(CStdModel):
    name = "memmove"

    def model(self, emulator: emulators.Emulator) -> None:
        # void *memmove(void *restrict dst, const void *restrict src, size_t n);
        dst = self.get_arg1(emulator)
        src = self.get_arg2(emulator)
        n = self.get_arg3(emulator)
        _emu_memcpy(emulator, dst, src, n)
        self.set_return_value(emulator, dst)


class Strcat(CStdModel):
    name = "strcat"

    def model(self, emulator: emulators.Emulator) -> None:
        # char *strcat(char *restrict s1, const char *restrict s2);
        dst = self.get_arg1(emulator)
        src = self.get_arg2(emulator)
        _emu_strncat(emulator, dst, src, MAX_STRLEN)
        self.set_return_value(emulator, dst)


class Strncat(CStdModel):
    name = "strncat"

    def model(self, emulator: emulators.Emulator) -> None:
        # char *strncat(char *restrict s1, const char *restrict s2, size_t n);
        dst = self.get_arg1(emulator)
        src = self.get_arg2(emulator)
        n = self.get_arg3(emulator)
        _emu_strncat(emulator, dst, src, n)
        self.set_return_value(emulator, dst)


class Memcmp(CStdModel):
    name = "memcmp"

    def model(self, emulator: emulators.Emulator) -> None:
        # int memcmp(coonst void *ptr1, const void *ptr2, size_t n);
        ptr1 = self.get_arg1(emulator)
        ptr2 = self.get_arg2(emulator)
        n = self.get_arg3(emulator)
        res = _emu_memcmp(emulator, ptr1, ptr2, n)
        self.set_return_value(emulator, res)


class Strncmp(CStdModel):
    name = "strncmp"

    def model(self, emulator: emulators.Emulator) -> None:
        # int strcmp(const char *ptr1, const char *ptr2, size_t n);
        ptr1 = self.get_arg1(emulator)
        ptr2 = self.get_arg2(emulator)
        n = self.get_arg3(emulator)
        res = _emu_strncmp(emulator, ptr1, ptr2, n)
        self.set_return_value(emulator, res)


class Strcmp(CStdModel):
    name = "strncmp"

    def model(self, emulator: emulators.Emulator) -> None:
        # int strcmp(const char *ptr1, const char *ptr2, size_t n);
        ptr1 = self.get_arg1(emulator)
        ptr2 = self.get_arg2(emulator)
        res = _emu_strncmp(emulator, ptr1, ptr2, MAX_STRLEN)
        self.set_return_value(emulator, res)


class Strcoll(CStdModel):
    name = "strcoll"

    def __init__(self, address: int):
        super().__init__(address)
        # NOTE: This requries extra configuration; set `locale` to the preferred locale.
        # TODO: Think of a way to support dynamically-changing locales.
        self.locale = ""

    def model(self, emulator: emulators.Emulator) -> None:
        # int strcoll(const char *str1, const char *str2);

        ptr1 = self.get_arg1(emulator)
        ptr2 = self.get_arg2(emulator)

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

    def __init__(self, address: int):
        super().__init__(address)
        # NOTE: This requries extra configuration; set `locale` to the preferred locale.
        # TODO: Think of a way to support dynamically-changing locales.
        self.locale = ""

    def model(self, emulator: emulators.Emulator) -> None:
        # size_t strxfrm(char *dst, const char *src, size_t n);
        dst = self.get_arg1(emulator)
        src = self.get_arg2(emulator)
        n = self.get_arg3(emulator)

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

    def model(self, emulator: emulators.Emulator) -> None:
        # const void *memchr(const void *ptr, int value, size_t n);
        ptr = self.get_arg1(emulator)
        val = self.get_arg2(emulator)
        n = self.get_arg3(emulator)

        data = emulator.read_memory(ptr, n)
        for i in range(0, n):
            if data[i] == val:
                self.set_return_value(emulator, ptr + i)
                return

        self.set_return_value(emulator, 0)


class Strchr(CStdModel):
    name = "strchr"

    def model(self, emulator: emulators.Emulator) -> None:
        # const char *memchr(const char *ptr, int value);
        ptr = self.get_arg1(emulator)
        val = self.get_arg2(emulator)

        n = _emu_strlen(emulator, ptr)

        data = emulator.read_memory(ptr, n)
        for i in range(0, n):
            if data[i] == val:
                self.set_return_value(emulator, ptr + i)
                return

        self.set_return_value(emulator, 0)


class Strcspn(CStdModel):
    name = "strcspn"

    def model(self, emulator: emulators.Emulator) -> None:
        # size_t strcspn(const char *str1, const char *str2);
        ptr1 = self.get_arg1(emulator)
        ptr2 = self.get_arg2(emulator)

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

    def model(self, emulator: emulators.Emulator) -> None:
        # const char *strpbrk(const char *str1, const char *str2);
        ptr1 = self.get_arg1(emulator)
        ptr2 = self.get_arg2(emulator)

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

    def model(self, emulator: emulators.Emulator) -> None:
        # size_t strspn(const char *str, int val);
        ptr = self.get_arg1(emulator)
        val = self.get_arg2(emulator)

        n = _emu_strlen(emulator, ptr)

        data = emulator.read_memory(ptr, n)

        for i in range(n - 1, -1, -1):
            if data[i] == val:
                self.set_return_value(emulator, ptr + i)
                return

        self.set_return_value(emulator, 0)


class Strspn(CStdModel):
    name = "strspn"

    def model(self, emulator: emulators.Emulator) -> None:
        # size_t strspn(const char *str1, const char *str2);
        ptr1 = self.get_arg1(emulator)
        ptr2 = self.get_arg2(emulator)

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

    def model(self, emulator: emulators.Emulator) -> None:
        # const char *strstr(const char *str1, const char *str2);
        ptr1 = self.get_arg1(emulator)
        ptr2 = self.get_arg2(emulator)

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

    def __init__(self, address: int):
        super().__init__(address)
        self.ptr = 0

    def model(self, emulator: emulators.Emulator) -> None:
        # char *strtok(char *str, const char *delimiters);
        ptr1 = self.get_arg1(emulator)
        ptr2 = self.get_arg2(emulator)

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

    def model(self, emulator: emulators.Emulator) -> None:
        # void *memset(void *ptr, int value, size_t num);
        ptr = self.get_arg1(emulator)
        val = self.get_arg2(emulator)
        n = self.get_arg3(emulator)

        data = bytes([val & 0xFF]) * n
        emulator.write_memory(ptr, data)

        self.set_return_value(emulator, ptr)


class Strerror(CStdModel):
    name = "strerror"

    def model(self, emulator: emulators.Emulator) -> None:
        # const char *strerror(int errno);
        # TODO: Figure out strerror
        # This devolves into a titanic, platform-specific table lookup.
        # The biggest problem is the platform-specific bit;
        # it goes beyond ISA/ABI and into OS version.
        raise NotImplementedError()


class Strlen(CStdModel):
    name = "strlen"

    def model(self, emulator: emulators.Emulator) -> None:
        # size_t strlen(const char *str);
        ptr = self.get_arg1(emulator)
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
