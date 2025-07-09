from ....c99 import (
    Clearerror,
    Fclose,
    Feof,
    Ferror,
    Fflush,
    Fgetc,
    Fgetpos,
    Fgets,
    Fopen,
    Fprintf,
    Fputc,
    Fputs,
    Fread,
    Freopen,
    Fscanf,
    Fseek,
    Fsetpos,
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
    Tmpfile,
    Tmpnam,
    Ungetc,
)
from ..systemv import MIPSSysVModel


class MIPSSysVFclose(Fclose, MIPSSysVModel):
    pass


class MIPSSysVFeof(Feof, MIPSSysVModel):
    pass


class MIPSSysVFerror(Ferror, MIPSSysVModel):
    pass


class MIPSSysVFgetc(Fgetc, MIPSSysVModel):
    pass


class MIPSSysVFgets(Fgets, MIPSSysVModel):
    pass


class MIPSSysVFopen(Fopen, MIPSSysVModel):
    pass


class MIPSSysVFprintf(Fprintf, MIPSSysVModel):
    pass


class MIPSSysVFputc(Fputc, MIPSSysVModel):
    pass


class MIPSSysVFputs(Fputs, MIPSSysVModel):
    pass


class MIPSSysVFread(Fread, MIPSSysVModel):
    pass


class MIPSSysVFscanf(Fscanf, MIPSSysVModel):
    pass


class MIPSSysVFseek(Fseek, MIPSSysVModel):
    pass


class MIPSSysVFtell(Ftell, MIPSSysVModel):
    pass


class MIPSSysVFwrite(Fwrite, MIPSSysVModel):
    pass


class MIPSSysVGetc(Getc, MIPSSysVModel):
    pass


class MIPSSysVGetchar(Getchar, MIPSSysVModel):
    pass


class MIPSSysVPrintf(Printf, MIPSSysVModel):
    pass


class MIPSSysVPutc(Putc, MIPSSysVModel):
    pass


class MIPSSysVPutchar(Putchar, MIPSSysVModel):
    pass


class MIPSSysVPuts(Puts, MIPSSysVModel):
    pass


class MIPSSysVRemove(Remove, MIPSSysVModel):
    pass


class MIPSSysVRename(Rename, MIPSSysVModel):
    pass


class MIPSSysVRewind(Rewind, MIPSSysVModel):
    pass


class MIPSSysVScanf(Scanf, MIPSSysVModel):
    pass


class MIPSSysVSnprintf(Snprintf, MIPSSysVModel):
    pass


class MIPSSysVSprintf(Sprintf, MIPSSysVModel):
    pass


class MIPSSysVSscanf(Sscanf, MIPSSysVModel):
    pass


class MIPSSysVClearerror(Clearerror, MIPSSysVModel):
    pass


class MIPSSysVFflush(Fflush, MIPSSysVModel):
    pass


class MIPSSysVFreopen(Freopen, MIPSSysVModel):
    pass


class MIPSSysVFgetpos(Fgetpos, MIPSSysVModel):
    pass


class MIPSSysVFsetpos(Fsetpos, MIPSSysVModel):
    pass


class MIPSSysVTmpfile(Tmpfile, MIPSSysVModel):
    pass


class MIPSSysVTmpnam(Tmpnam, MIPSSysVModel):
    pass


class MIPSSysVUngetc(Ungetc, MIPSSysVModel):
    pass


__all__ = [
    "MIPSSysVFclose",
    "MIPSSysVFeof",
    "MIPSSysVFerror",
    "MIPSSysVFgetc",
    "MIPSSysVFgets",
    "MIPSSysVFopen",
    "MIPSSysVFprintf",
    "MIPSSysVFputc",
    "MIPSSysVFputs",
    "MIPSSysVFread",
    "MIPSSysVFscanf",
    "MIPSSysVFseek",
    "MIPSSysVFtell",
    "MIPSSysVFwrite",
    "MIPSSysVGetc",
    "MIPSSysVGetchar",
    "MIPSSysVPrintf",
    "MIPSSysVPutc",
    "MIPSSysVPutchar",
    "MIPSSysVPuts",
    "MIPSSysVRemove",
    "MIPSSysVRename",
    "MIPSSysVRewind",
    "MIPSSysVScanf",
    "MIPSSysVSnprintf",
    "MIPSSysVSprintf",
    "MIPSSysVSscanf",
    "MIPSSysVClearerror",
    "MIPSSysVFflush",
    "MIPSSysVFreopen",
    "MIPSSysVFgetpos",
    "MIPSSysVFsetpos",
    "MIPSSysVTmpfile",
    "MIPSSysVTmpnam",
    "MIPSSysVUngetc",
]
