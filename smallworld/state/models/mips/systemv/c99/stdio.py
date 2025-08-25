from ....c99 import (
    Clearerr,
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
    Gets,
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
    Vfprintf,
    Vfscanf,
    Vprintf,
    Vscanf,
    Vsnprintf,
    Vsprintf,
    Vsscanf,
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


class MIPSSysVGets(Gets, MIPSSysVModel):
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


class MIPSSysVClearerr(Clearerr, MIPSSysVModel):
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


class MIPSSysVVfprintf(Vfprintf, MIPSSysVModel):
    pass


class MIPSSysVVfscanf(Vfscanf, MIPSSysVModel):
    pass


class MIPSSysVVprintf(Vprintf, MIPSSysVModel):
    pass


class MIPSSysVVscanf(Vscanf, MIPSSysVModel):
    pass


class MIPSSysVVsnprintf(Vsnprintf, MIPSSysVModel):
    pass


class MIPSSysVVsprintf(Vsprintf, MIPSSysVModel):
    pass


class MIPSSysVVsscanf(Vsscanf, MIPSSysVModel):
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
    "MIPSSysVGets",
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
    "MIPSSysVClearerr",
    "MIPSSysVFflush",
    "MIPSSysVFreopen",
    "MIPSSysVFgetpos",
    "MIPSSysVFsetpos",
    "MIPSSysVTmpfile",
    "MIPSSysVTmpnam",
    "MIPSSysVUngetc",
    "MIPSSysVVfprintf",
    "MIPSSysVVfscanf",
    "MIPSSysVVprintf",
    "MIPSSysVVscanf",
    "MIPSSysVVsnprintf",
    "MIPSSysVVsprintf",
    "MIPSSysVVsscanf",
]
