from ....c99.string import (
    Memchr,
    Memcmp,
    Memcpy,
    Memmove,
    Memset,
    Strcat,
    Strchr,
    Strcmp,
    Strcoll,
    Strcpy,
    Strcspn,
    Strerror,
    Strlen,
    Strncat,
    Strncmp,
    Strncpy,
    Strpbrk,
    Strrchr,
    Strspn,
    Strstr,
    Strtok,
    Strxfrm,
)
from ....cstd import ArgumentType
from ..sdccstackauto import MCS51SDCCStackAutoModel


class MCS51SDCCStackAutoMemchr(Memchr, MCS51SDCCStackAutoModel):
    pass


class MCS51SDCCStackAutoMemcmp(Memcmp, MCS51SDCCStackAutoModel):
    pass


class MCS51SDCCStackAutoMemcpy(Memcpy, MCS51SDCCStackAutoModel):
    pass


class MCS51SDCCStackAutoMemmove(Memmove, MCS51SDCCStackAutoModel):
    pass


class MCS51SDCCStackAutoMemset(Memset, MCS51SDCCStackAutoModel):
    # SDCC narrows the character argument on the 8051:
    # void *memset(void *s, unsigned char c, size_t n);
    argument_types = [ArgumentType.POINTER, ArgumentType.UCHAR, ArgumentType.SIZE_T]


class MCS51SDCCStackAutoStrcat(Strcat, MCS51SDCCStackAutoModel):
    pass


class MCS51SDCCStackAutoStrchr(Strchr, MCS51SDCCStackAutoModel):
    # SDCC narrows the character argument on the 8051:
    # char *strchr(const char *s, char c);
    argument_types = [ArgumentType.POINTER, ArgumentType.CHAR]


class MCS51SDCCStackAutoStrcmp(Strcmp, MCS51SDCCStackAutoModel):
    pass


class MCS51SDCCStackAutoStrcoll(Strcoll, MCS51SDCCStackAutoModel):
    pass


class MCS51SDCCStackAutoStrcpy(Strcpy, MCS51SDCCStackAutoModel):
    pass


class MCS51SDCCStackAutoStrcspn(Strcspn, MCS51SDCCStackAutoModel):
    pass


class MCS51SDCCStackAutoStrerror(Strerror, MCS51SDCCStackAutoModel):
    pass


class MCS51SDCCStackAutoStrlen(Strlen, MCS51SDCCStackAutoModel):
    pass


class MCS51SDCCStackAutoStrncat(Strncat, MCS51SDCCStackAutoModel):
    pass


class MCS51SDCCStackAutoStrncmp(Strncmp, MCS51SDCCStackAutoModel):
    pass


class MCS51SDCCStackAutoStrncpy(Strncpy, MCS51SDCCStackAutoModel):
    pass


class MCS51SDCCStackAutoStrpbrk(Strpbrk, MCS51SDCCStackAutoModel):
    pass


class MCS51SDCCStackAutoStrrchr(Strrchr, MCS51SDCCStackAutoModel):
    # SDCC narrows the character argument on the 8051:
    # char *strrchr(const char *s, char c);
    argument_types = [ArgumentType.POINTER, ArgumentType.CHAR]


class MCS51SDCCStackAutoStrspn(Strspn, MCS51SDCCStackAutoModel):
    pass


class MCS51SDCCStackAutoStrstr(Strstr, MCS51SDCCStackAutoModel):
    pass


class MCS51SDCCStackAutoStrtok(Strtok, MCS51SDCCStackAutoModel):
    pass


class MCS51SDCCStackAutoStrxfrm(Strxfrm, MCS51SDCCStackAutoModel):
    pass


__all__ = [
    "MCS51SDCCStackAutoMemchr",
    "MCS51SDCCStackAutoMemcmp",
    "MCS51SDCCStackAutoMemcpy",
    "MCS51SDCCStackAutoMemmove",
    "MCS51SDCCStackAutoMemset",
    "MCS51SDCCStackAutoStrcat",
    "MCS51SDCCStackAutoStrchr",
    "MCS51SDCCStackAutoStrcmp",
    "MCS51SDCCStackAutoStrcoll",
    "MCS51SDCCStackAutoStrcpy",
    "MCS51SDCCStackAutoStrcspn",
    "MCS51SDCCStackAutoStrerror",
    "MCS51SDCCStackAutoStrlen",
    "MCS51SDCCStackAutoStrncat",
    "MCS51SDCCStackAutoStrncmp",
    "MCS51SDCCStackAutoStrncpy",
    "MCS51SDCCStackAutoStrpbrk",
    "MCS51SDCCStackAutoStrrchr",
    "MCS51SDCCStackAutoStrspn",
    "MCS51SDCCStackAutoStrstr",
    "MCS51SDCCStackAutoStrtok",
    "MCS51SDCCStackAutoStrxfrm",
]
