from .... import emulators, exceptions
from ..cstd import ArgumentType, CStdModel
from ..errno import ErrnoResolver
from .utils import (
    MAX_STRLEN,
    _emu_memcmp,
    _emu_memcpy,
    _emu_strlen,
    _emu_strncat,
    _emu_strncmp,
    _emu_strncpy,
)


class Memcpy(CStdModel):
    name = "memcpy"

    # void *memcpy(void *restrict dst, const void *restrict src, size_t n);
    argument_types = [ArgumentType.POINTER, ArgumentType.POINTER, ArgumentType.SIZE_T]
    return_type = ArgumentType.POINTER

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)
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
        super().model(emulator)
        dst = self.get_arg1(emulator)
        src = self.get_arg2(emulator)
        n = self.get_arg3(emulator)

        assert isinstance(dst, int)
        assert isinstance(src, int)
        assert isinstance(n, int)

        _emu_memcpy(emulator, dst, src, n)
        self.set_return_value(emulator, dst)


class Strcpy(CStdModel):
    name = "strcpy"

    # char *strcpy(char *dst, const char *src);
    argument_types = [ArgumentType.POINTER, ArgumentType.POINTER]
    return_type = ArgumentType.POINTER

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)
        dst = self.get_arg1(emulator)
        src = self.get_arg2(emulator)

        assert isinstance(dst, int)
        assert isinstance(src, int)

        n = _emu_strlen(emulator, src) + 1

        _emu_memcpy(emulator, dst, src, n)
        self.set_return_value(emulator, dst)


class Strncpy(CStdModel):
    name = "strncpy"

    # char *strcpy(char *dst, const char *src, size_t n);
    argument_types = [ArgumentType.POINTER, ArgumentType.POINTER, ArgumentType.SIZE_T]
    return_type = ArgumentType.POINTER

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)
        dst = self.get_arg1(emulator)
        src = self.get_arg2(emulator)
        n = self.get_arg3(emulator)

        assert isinstance(dst, int)
        assert isinstance(src, int)
        assert isinstance(n, int)

        _emu_strncpy(emulator, dst, src, n)
        self.set_return_value(emulator, dst)


class Strcat(CStdModel):
    name = "strcat"

    # char *strcat(char *restrict s1, const char *restrict s2);
    argument_types = [ArgumentType.POINTER, ArgumentType.POINTER]
    return_type = ArgumentType.POINTER

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)
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
        super().model(emulator)
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
        super().model(emulator)
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
        super().model(emulator)
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
        super().model(emulator)
        # int strcmp(const char *ptr1, const char *ptr2);
        ptr1 = self.get_arg1(emulator)
        ptr2 = self.get_arg2(emulator)

        assert isinstance(ptr1, int)
        assert isinstance(ptr2, int)

        res = _emu_strncmp(emulator, ptr1, ptr2, MAX_STRLEN)
        self.set_return_value(emulator, res)


#: Locale names whose collation is plain bytewise (C/POSIX) order. Only these
#: are modeled by strcoll/strxfrm.
_C_LOCALES = frozenset({"", "C", "POSIX", "C.UTF-8"})


def _require_c_locale(name: str, loc: str) -> None:
    """Refuse a non-C locale rather than delegating to the host process.

    strcoll/strxfrm collation outside the C/POSIX locale needs the target's
    locale data, which we can't observe under emulation. The old models faked
    it by mutating the host process locale -- both non-deterministic and a
    global side effect -- so an unsupported locale is now an explicit error.
    """
    if loc not in _C_LOCALES:
        raise exceptions.UnsupportedModelError(
            f"{name} only models the C/POSIX locale; got {loc!r}"
        )


class Strcoll(CStdModel):
    name = "strcoll"

    # int strcoll(const void *ptr1, const void *ptr2);
    argument_types = [ArgumentType.POINTER, ArgumentType.POINTER]
    return_type = ArgumentType.INT

    def __init__(self, address: int):
        super().__init__(address)
        # Only the C/POSIX locale is modeled; see _require_c_locale.
        self.locale = ""

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)
        _require_c_locale(self.name, self.locale)
        ptr1 = self.get_arg1(emulator)
        ptr2 = self.get_arg2(emulator)

        assert isinstance(ptr1, int)
        assert isinstance(ptr2, int)

        bytes1 = emulator.read_memory(ptr1, _emu_strlen(emulator, ptr1))
        bytes2 = emulator.read_memory(ptr2, _emu_strlen(emulator, ptr2))

        # In the C/POSIX locale strcoll collates bytewise -- it is strcmp --
        # and Python's bytes comparison is the same unsigned lexicographic
        # order, so this needs no host libc and no locale state.
        res = (bytes1 > bytes2) - (bytes1 < bytes2)
        self.set_return_value(emulator, res)


class Strxfrm(CStdModel):
    name = "strxfrm"

    # size_t strxfrm(char *dst, const char *src, size_t n);
    argument_types = [ArgumentType.POINTER, ArgumentType.POINTER, ArgumentType.SIZE_T]
    return_type = ArgumentType.SIZE_T

    def __init__(self, address: int):
        super().__init__(address)
        # See Strcoll: only the C/POSIX locale is modeled.
        self.locale = ""

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)
        _require_c_locale(self.name, self.locale)
        dst = self.get_arg1(emulator)
        src = self.get_arg2(emulator)
        n = self.get_arg3(emulator)

        assert isinstance(dst, int)
        assert isinstance(src, int)
        assert isinstance(n, int)

        # In the C/POSIX locale the transform is the identity, so the
        # transformed length is strlen(src). C returns that length (excluding
        # the NUL) regardless of n or dst.
        srclen = _emu_strlen(emulator, src)
        self.set_return_value(emulator, srclen)

        # n bounds the DESTINATION buffer, including the NUL. With n == 0 or a
        # NULL dst nothing is written; otherwise write at most n bytes, always
        # NUL-terminated. (C leaves dst indeterminate when srclen + 1 > n, so a
        # truncated-but-terminated copy is a valid concrete result.)
        if dst == 0 or n == 0:
            return

        src_bytes = emulator.read_memory(src, srclen)
        out = src_bytes[: n - 1] + b"\x00"
        emulator.write_memory(dst, out)


class Memchr(CStdModel):
    name = "memchr"

    # const void *memchr(const void *ptr, int value, size_t n);
    argument_types = [ArgumentType.POINTER, ArgumentType.INT, ArgumentType.SIZE_T]
    return_type = ArgumentType.POINTER

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)
        # const void *memchr(const void *ptr, int value, size_t n);
        ptr = self.get_arg1(emulator)
        val = self.get_arg2(emulator)
        n = self.get_arg3(emulator)

        assert isinstance(ptr, int)
        assert isinstance(val, int)
        assert isinstance(n, int)

        data = emulator.read_memory(ptr, n)
        if 0 <= val <= 255:
            idx = data.find(bytes([val]))
            if idx != -1:
                self.set_return_value(emulator, ptr + idx)
                return

        self.set_return_value(emulator, 0)


class Strchr(CStdModel):
    name = "strchr"

    # const char *strchr(const char *ptr, int value);
    argument_types = [ArgumentType.POINTER, ArgumentType.INT]
    return_type = ArgumentType.POINTER

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)
        ptr = self.get_arg1(emulator)
        val = self.get_arg2(emulator)

        assert isinstance(ptr, int)
        assert isinstance(val, int)

        n = _emu_strlen(emulator, ptr)

        data = emulator.read_memory(ptr, n)
        if 0 <= val <= 255:
            idx = data.find(bytes([val]))
            if idx != -1:
                self.set_return_value(emulator, ptr + idx)
                return

        self.set_return_value(emulator, 0)


class Strcspn(CStdModel):
    name = "strcspn"

    # size_t strcspn(const char *str1, const char *str2);
    argument_types = [ArgumentType.POINTER, ArgumentType.POINTER]
    return_type = ArgumentType.SIZE_T

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)
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
        super().model(emulator)
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
        super().model(emulator)
        ptr = self.get_arg1(emulator)
        val = self.get_arg2(emulator)

        assert isinstance(ptr, int)
        assert isinstance(val, int)

        n = _emu_strlen(emulator, ptr)

        data = emulator.read_memory(ptr, n)

        if 0 <= val <= 255:
            idx = data.rfind(bytes([val]))
            if idx != -1:
                self.set_return_value(emulator, ptr + idx)
                return

        self.set_return_value(emulator, 0)


class Strspn(CStdModel):
    name = "strspn"

    # size_t strspn(const char *str1, const char *str2);
    argument_types = [ArgumentType.POINTER, ArgumentType.POINTER]
    return_type = ArgumentType.SIZE_T

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)
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
        super().model(emulator)
        ptr1 = self.get_arg1(emulator)
        ptr2 = self.get_arg2(emulator)

        assert isinstance(ptr1, int)
        assert isinstance(ptr2, int)

        len1 = _emu_strlen(emulator, ptr1)
        len2 = _emu_strlen(emulator, ptr2)

        bytes1 = emulator.read_memory(ptr1, len1)
        bytes2 = emulator.read_memory(ptr2, len2)

        if len1 == 0:
            # Preserve existing behavior: an empty haystack returns NULL,
            # even for an empty needle (the original loop never executed).
            self.set_return_value(emulator, 0)
            return

        idx = bytes1.find(bytes2)
        if idx != -1:
            self.set_return_value(emulator, ptr1 + idx)
        else:
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
        super().model(emulator)
        ptr1 = self.get_arg1(emulator)
        ptr2 = self.get_arg2(emulator)

        assert isinstance(ptr1, int)
        assert isinstance(ptr2, int)

        if ptr1 == 0:
            if self.ptr == 0:
                raise exceptions.EmulationError(
                    "strtok called with NULL when placeholder was NULL"
                )
            ptr1 = self.ptr

        len1 = _emu_strlen(emulator, ptr1)
        len2 = _emu_strlen(emulator, ptr2)

        bytes1 = emulator.read_memory(ptr1, len1)
        bytes2 = emulator.read_memory(ptr2, len2)

        if len1 == 0:
            # Empty string; we're out of tokens.
            self.set_return_value(emulator, 0)
            self.ptr = 0
            return

        needles = {x for x in bytes2}

        # C strtok skips any leading delimiters before the token starts.
        start = 0
        while start < len1 and bytes1[start] in needles:
            start += 1

        if start == len1:
            # Remaining string is all delimiters; no token left.
            self.set_return_value(emulator, 0)
            self.ptr = 0
            return

        # The token begins at the first non-delimiter character.
        self.set_return_value(emulator, ptr1 + start)

        for i in range(start, len1):
            if bytes1[i] in needles:
                emulator.write_memory(ptr1 + i, b"\0")
                self.ptr = ptr1 + i + 1
                return

        # Fall-through case; token lasts to end of string
        self.ptr = ptr1 + len1


class Memset(CStdModel):
    name = "memset"

    # void *memset(void *ptr, int value, size_t num);
    argument_types = [ArgumentType.POINTER, ArgumentType.INT, ArgumentType.SIZE_T]
    return_type = ArgumentType.POINTER

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)
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

    # Needs a string buffer for the description
    static_space_required = 64

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        errno = self.get_arg1(emulator)

        assert isinstance(errno, int)

        resolver = ErrnoResolver.for_platform(self.platform, self.abi)

        try:
            description = resolver.get_description(errno)
        except KeyError:
            description = f"Unknown error {errno}"

        descbytes = description.encode("utf-8") + b"\0"

        assert len(descbytes) <= self.static_space_required
        assert isinstance(self.static_buffer_address, int)
        emulator.write_memory(self.static_buffer_address, descbytes)
        self.set_return_value(emulator, self.static_buffer_address)


class Strlen(CStdModel):
    name = "strlen"

    # size_t strlen(const char *str);
    argument_types = [ArgumentType.POINTER]
    return_type = ArgumentType.SIZE_T

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)
        ptr = self.get_arg1(emulator)

        assert isinstance(ptr, int)

        res = _emu_strlen(emulator, ptr)
        self.set_return_value(emulator, res)


__all__ = [
    "Memcpy",
    "Memmove",
    "Strcpy",
    "Strncpy",
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
