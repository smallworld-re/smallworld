from ....c99 import (
    Fclose,
    Feof,
    Ferror,
    Fgetc,
    Fgets,
    Fopen,
    Fprintf,
    Fputc,
    Fputs,
    Fread,
    Fscanf,
    Fseek,
    Ftell,
    Fwrite,
    Getc,
    Getchar,
    Printf,
    Putc,
    Putchar,
    Puts,
    Remove,
    Rename,
    Rewind,
    Scanf,
    Snprintf,
    Sprintf,
    Sscanf,
)
from ..systemv import AMD64SysVModel


class AMD64SysVFclose(Fclose, AMD64SysVModel):
    pass


class AMD64SysVFeof(Feof, AMD64SysVModel):
    pass


class AMD64SysVFerror(Ferror, AMD64SysVModel):
    pass


class AMD64SysVFgetc(Fgetc, AMD64SysVModel):
    pass


class AMD64SysVFgets(Fgets, AMD64SysVModel):
    pass


class AMD64SysVFopen(Fopen, AMD64SysVModel):
    pass


class AMD64SysVFprintf(Fprintf, AMD64SysVModel):
    pass


class AMD64SysVFputc(Fputc, AMD64SysVModel):
    pass


class AMD64SysVFputs(Fputs, AMD64SysVModel):
    pass


class AMD64SysVFread(Fread, AMD64SysVModel):
    pass


class AMD64SysVFscanf(Fscanf, AMD64SysVModel):
    pass


class AMD64SysVFseek(Fseek, AMD64SysVModel):
    pass


class AMD64SysVFtell(Ftell, AMD64SysVModel):
    pass


class AMD64SysVFwrite(Fwrite, AMD64SysVModel):
    pass


class AMD64SysVGetc(Getc, AMD64SysVModel):
    pass


class AMD64SysVGetchar(Getchar, AMD64SysVModel):
    pass


class AMD64SysVPrintf(Printf, AMD64SysVModel):
    pass


class AMD64SysVPutc(Putc, AMD64SysVModel):
    pass


class AMD64SysVPutchar(Putchar, AMD64SysVModel):
    pass


class AMD64SysVPuts(Puts, AMD64SysVModel):
    pass


class AMD64SysVRemove(Remove, AMD64SysVModel):
    pass


class AMD64SysVRename(Rename, AMD64SysVModel):
    pass


class AMD64SysVRewind(Rewind, AMD64SysVModel):
    pass


class AMD64SysVScanf(Scanf, AMD64SysVModel):
    pass


class AMD64SysVSnprintf(Snprintf, AMD64SysVModel):
    pass


class AMD64SysVSprintf(Sprintf, AMD64SysVModel):
    pass


class AMD64SysVSscanf(Sscanf, AMD64SysVModel):
    pass


__all__ = [
    "AMD64SysVFclose",
    "AMD64SysVFeof",
    "AMD64SysVFerror",
    "AMD64SysVFgetc",
    "AMD64SysVFgets",
    "AMD64SysVFopen",
    "AMD64SysVFprintf",
    "AMD64SysVFputc",
    "AMD64SysVFputs",
    "AMD64SysVFread",
    "AMD64SysVFscanf",
    "AMD64SysVFseek",
    "AMD64SysVFtell",
    "AMD64SysVFwrite",
    "AMD64SysVGetc",
    "AMD64SysVGetchar",
    "AMD64SysVPrintf",
    "AMD64SysVPutc",
    "AMD64SysVPutchar",
    "AMD64SysVPuts",
    "AMD64SysVRemove",
    "AMD64SysVRename",
    "AMD64SysVRewind",
    "AMD64SysVScanf",
    "AMD64SysVSnprintf",
    "AMD64SysVSprintf",
    "AMD64SysVSscanf",
]
