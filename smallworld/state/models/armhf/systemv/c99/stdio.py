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
from ..systemv import ArmHFSysVModel


class ArmHFSysVFclose(Fclose, ArmHFSysVModel):
    pass


class ArmHFSysVFeof(Feof, ArmHFSysVModel):
    pass


class ArmHFSysVFerror(Ferror, ArmHFSysVModel):
    pass


class ArmHFSysVFgetc(Fgetc, ArmHFSysVModel):
    pass


class ArmHFSysVFgets(Fgets, ArmHFSysVModel):
    pass


class ArmHFSysVFopen(Fopen, ArmHFSysVModel):
    pass


class ArmHFSysVFprintf(Fprintf, ArmHFSysVModel):
    pass


class ArmHFSysVFputc(Fputc, ArmHFSysVModel):
    pass


class ArmHFSysVFputs(Fputs, ArmHFSysVModel):
    pass


class ArmHFSysVFread(Fread, ArmHFSysVModel):
    pass


class ArmHFSysVFscanf(Fscanf, ArmHFSysVModel):
    pass


class ArmHFSysVFseek(Fseek, ArmHFSysVModel):
    pass


class ArmHFSysVFtell(Ftell, ArmHFSysVModel):
    pass


class ArmHFSysVFwrite(Fwrite, ArmHFSysVModel):
    pass


class ArmHFSysVGetc(Getc, ArmHFSysVModel):
    pass


class ArmHFSysVGetchar(Getchar, ArmHFSysVModel):
    pass


class ArmHFSysVPrintf(Printf, ArmHFSysVModel):
    pass


class ArmHFSysVPutc(Putc, ArmHFSysVModel):
    pass


class ArmHFSysVPutchar(Putchar, ArmHFSysVModel):
    pass


class ArmHFSysVPuts(Puts, ArmHFSysVModel):
    pass


class ArmHFSysVRemove(Remove, ArmHFSysVModel):
    pass


class ArmHFSysVRename(Rename, ArmHFSysVModel):
    pass


class ArmHFSysVRewind(Rewind, ArmHFSysVModel):
    pass


class ArmHFSysVScanf(Scanf, ArmHFSysVModel):
    pass


class ArmHFSysVSnprintf(Snprintf, ArmHFSysVModel):
    pass


class ArmHFSysVSprintf(Sprintf, ArmHFSysVModel):
    pass


class ArmHFSysVSscanf(Sscanf, ArmHFSysVModel):
    pass


__all__ = [
    "ArmHFSysVFclose",
    "ArmHFSysVFeof",
    "ArmHFSysVFerror",
    "ArmHFSysVFgetc",
    "ArmHFSysVFgets",
    "ArmHFSysVFopen",
    "ArmHFSysVFprintf",
    "ArmHFSysVFputc",
    "ArmHFSysVFputs",
    "ArmHFSysVFread",
    "ArmHFSysVFscanf",
    "ArmHFSysVFseek",
    "ArmHFSysVFtell",
    "ArmHFSysVFwrite",
    "ArmHFSysVGetc",
    "ArmHFSysVGetchar",
    "ArmHFSysVPrintf",
    "ArmHFSysVPutc",
    "ArmHFSysVPutchar",
    "ArmHFSysVPuts",
    "ArmHFSysVRemove",
    "ArmHFSysVRename",
    "ArmHFSysVRewind",
    "ArmHFSysVScanf",
    "ArmHFSysVSnprintf",
    "ArmHFSysVSprintf",
    "ArmHFSysVSscanf",
]
