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
from ..sdcc import MCS51SDCCModel


class MCS51SDCCMemchr(Memchr, MCS51SDCCModel):
    pass


class MCS51SDCCMemcmp(Memcmp, MCS51SDCCModel):
    pass


class MCS51SDCCMemcpy(Memcpy, MCS51SDCCModel):
    pass


class MCS51SDCCMemmove(Memmove, MCS51SDCCModel):
    pass


class MCS51SDCCMemset(Memset, MCS51SDCCModel):
    # SDCC narrows the character argument on the 8051:
    # void *memset(void *s, unsigned char c, size_t n);
    argument_types = [ArgumentType.POINTER, ArgumentType.UCHAR, ArgumentType.SIZE_T]


class MCS51SDCCStrcat(Strcat, MCS51SDCCModel):
    pass


class MCS51SDCCStrchr(Strchr, MCS51SDCCModel):
    # SDCC narrows the character argument on the 8051:
    # char *strchr(const char *s, char c);
    argument_types = [ArgumentType.POINTER, ArgumentType.CHAR]


class MCS51SDCCStrcmp(Strcmp, MCS51SDCCModel):
    pass


class MCS51SDCCStrcoll(Strcoll, MCS51SDCCModel):
    pass


class MCS51SDCCStrcpy(Strcpy, MCS51SDCCModel):
    pass


class MCS51SDCCStrcspn(Strcspn, MCS51SDCCModel):
    pass


class MCS51SDCCStrerror(Strerror, MCS51SDCCModel):
    pass


class MCS51SDCCStrlen(Strlen, MCS51SDCCModel):
    pass


class MCS51SDCCStrncat(Strncat, MCS51SDCCModel):
    pass


class MCS51SDCCStrncmp(Strncmp, MCS51SDCCModel):
    pass


class MCS51SDCCStrncpy(Strncpy, MCS51SDCCModel):
    pass


class MCS51SDCCStrpbrk(Strpbrk, MCS51SDCCModel):
    pass


class MCS51SDCCStrrchr(Strrchr, MCS51SDCCModel):
    # SDCC narrows the character argument on the 8051:
    # char *strrchr(const char *s, char c);
    argument_types = [ArgumentType.POINTER, ArgumentType.CHAR]


class MCS51SDCCStrspn(Strspn, MCS51SDCCModel):
    pass


class MCS51SDCCStrstr(Strstr, MCS51SDCCModel):
    pass


class MCS51SDCCStrtok(Strtok, MCS51SDCCModel):
    pass


class MCS51SDCCStrxfrm(Strxfrm, MCS51SDCCModel):
    pass


__all__ = [
    "MCS51SDCCMemchr",
    "MCS51SDCCMemcmp",
    "MCS51SDCCMemcpy",
    "MCS51SDCCMemmove",
    "MCS51SDCCMemset",
    "MCS51SDCCStrcat",
    "MCS51SDCCStrchr",
    "MCS51SDCCStrcmp",
    "MCS51SDCCStrcoll",
    "MCS51SDCCStrcpy",
    "MCS51SDCCStrcspn",
    "MCS51SDCCStrerror",
    "MCS51SDCCStrlen",
    "MCS51SDCCStrncat",
    "MCS51SDCCStrncmp",
    "MCS51SDCCStrncpy",
    "MCS51SDCCStrpbrk",
    "MCS51SDCCStrrchr",
    "MCS51SDCCStrspn",
    "MCS51SDCCStrstr",
    "MCS51SDCCStrtok",
    "MCS51SDCCStrxfrm",
]
