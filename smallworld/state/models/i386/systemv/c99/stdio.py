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
from ..systemv import I386SysVModel


class I386SysVFclose(Fclose, I386SysVModel):
    pass


class I386SysVFeof(Feof, I386SysVModel):
    pass


class I386SysVFerror(Ferror, I386SysVModel):
    pass


class I386SysVFgetc(Fgetc, I386SysVModel):
    pass


class I386SysVFgets(Fgets, I386SysVModel):
    pass


class I386SysVFopen(Fopen, I386SysVModel):
    pass


class I386SysVFprintf(Fprintf, I386SysVModel):
    pass


class I386SysVFputc(Fputc, I386SysVModel):
    pass


class I386SysVFputs(Fputs, I386SysVModel):
    pass


class I386SysVFread(Fread, I386SysVModel):
    pass


class I386SysVFscanf(Fscanf, I386SysVModel):
    pass


class I386SysVFseek(Fseek, I386SysVModel):
    pass


class I386SysVFtell(Ftell, I386SysVModel):
    pass


class I386SysVFwrite(Fwrite, I386SysVModel):
    pass


class I386SysVGetc(Getc, I386SysVModel):
    pass


class I386SysVGetchar(Getchar, I386SysVModel):
    pass


class I386SysVPrintf(Printf, I386SysVModel):
    pass


class I386SysVPutc(Putc, I386SysVModel):
    pass


class I386SysVPutchar(Putchar, I386SysVModel):
    pass


class I386SysVPuts(Puts, I386SysVModel):
    pass


class I386SysVRemove(Remove, I386SysVModel):
    pass


class I386SysVRename(Rename, I386SysVModel):
    pass


class I386SysVRewind(Rewind, I386SysVModel):
    pass


class I386SysVScanf(Scanf, I386SysVModel):
    pass


class I386SysVSnprintf(Snprintf, I386SysVModel):
    pass


class I386SysVSprintf(Sprintf, I386SysVModel):
    pass


class I386SysVSscanf(Sscanf, I386SysVModel):
    pass


__all__ = [
    "I386SysVFclose",
    "I386SysVFeof",
    "I386SysVFerror",
    "I386SysVFgetc",
    "I386SysVFgets",
    "I386SysVFopen",
    "I386SysVFprintf",
    "I386SysVFputc",
    "I386SysVFputs",
    "I386SysVFread",
    "I386SysVFscanf",
    "I386SysVFseek",
    "I386SysVFtell",
    "I386SysVFwrite",
    "I386SysVGetc",
    "I386SysVGetchar",
    "I386SysVPrintf",
    "I386SysVPutc",
    "I386SysVPutchar",
    "I386SysVPuts",
    "I386SysVRemove",
    "I386SysVRename",
    "I386SysVRewind",
    "I386SysVScanf",
    "I386SysVSnprintf",
    "I386SysVSprintf",
    "I386SysVSscanf",
]
