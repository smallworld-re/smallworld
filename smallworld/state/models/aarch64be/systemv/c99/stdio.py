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
    FprintfChk,
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
    Perror,
    Printf,
    PrintfChk,
    Putc,
    Putchar,
    Puts,
    Remove,
    Rename,
    Rewind,
    Scanf,
    Snprintf,
    SnprintfChk,
    Sprintf,
    SprintfChk,
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
from ..systemv import AArch64BESysVModel


class AArch64BESysVPerror(Perror, AArch64BESysVModel):
    pass


class AArch64BESysVPrintfChk(PrintfChk, AArch64BESysVModel):
    pass


class AArch64BESysVFprintfChk(FprintfChk, AArch64BESysVModel):
    pass


class AArch64BESysVSnprintfChk(SnprintfChk, AArch64BESysVModel):
    pass


class AArch64BESysVSprintfChk(SprintfChk, AArch64BESysVModel):
    pass


class AArch64BESysVFclose(Fclose, AArch64BESysVModel):
    pass


class AArch64BESysVFeof(Feof, AArch64BESysVModel):
    pass


class AArch64BESysVFerror(Ferror, AArch64BESysVModel):
    pass


class AArch64BESysVFgetc(Fgetc, AArch64BESysVModel):
    pass


class AArch64BESysVFgets(Fgets, AArch64BESysVModel):
    pass


class AArch64BESysVFopen(Fopen, AArch64BESysVModel):
    pass


class AArch64BESysVFprintf(Fprintf, AArch64BESysVModel):
    pass


class AArch64BESysVFputc(Fputc, AArch64BESysVModel):
    pass


class AArch64BESysVFputs(Fputs, AArch64BESysVModel):
    pass


class AArch64BESysVFread(Fread, AArch64BESysVModel):
    pass


class AArch64BESysVFscanf(Fscanf, AArch64BESysVModel):
    pass


class AArch64BESysVFseek(Fseek, AArch64BESysVModel):
    pass


class AArch64BESysVFtell(Ftell, AArch64BESysVModel):
    pass


class AArch64BESysVFwrite(Fwrite, AArch64BESysVModel):
    pass


class AArch64BESysVGetc(Getc, AArch64BESysVModel):
    pass


class AArch64BESysVGetchar(Getchar, AArch64BESysVModel):
    pass


class AArch64BESysVGets(Gets, AArch64BESysVModel):
    pass


class AArch64BESysVPrintf(Printf, AArch64BESysVModel):
    pass


class AArch64BESysVPutc(Putc, AArch64BESysVModel):
    pass


class AArch64BESysVPutchar(Putchar, AArch64BESysVModel):
    pass


class AArch64BESysVPuts(Puts, AArch64BESysVModel):
    pass


class AArch64BESysVRemove(Remove, AArch64BESysVModel):
    pass


class AArch64BESysVRename(Rename, AArch64BESysVModel):
    pass


class AArch64BESysVRewind(Rewind, AArch64BESysVModel):
    pass


class AArch64BESysVScanf(Scanf, AArch64BESysVModel):
    pass


class AArch64BESysVSnprintf(Snprintf, AArch64BESysVModel):
    pass


class AArch64BESysVSprintf(Sprintf, AArch64BESysVModel):
    pass


class AArch64BESysVSscanf(Sscanf, AArch64BESysVModel):
    pass


class AArch64BESysVClearerr(Clearerr, AArch64BESysVModel):
    pass


class AArch64BESysVFflush(Fflush, AArch64BESysVModel):
    pass


class AArch64BESysVFreopen(Freopen, AArch64BESysVModel):
    pass


class AArch64BESysVFgetpos(Fgetpos, AArch64BESysVModel):
    pass


class AArch64BESysVFsetpos(Fsetpos, AArch64BESysVModel):
    pass


class AArch64BESysVTmpfile(Tmpfile, AArch64BESysVModel):
    pass


class AArch64BESysVTmpnam(Tmpnam, AArch64BESysVModel):
    pass


class AArch64BESysVUngetc(Ungetc, AArch64BESysVModel):
    pass


class AArch64BESysVVfprintf(Vfprintf, AArch64BESysVModel):
    pass


class AArch64BESysVVfscanf(Vfscanf, AArch64BESysVModel):
    pass


class AArch64BESysVVprintf(Vprintf, AArch64BESysVModel):
    pass


class AArch64BESysVVscanf(Vscanf, AArch64BESysVModel):
    pass


class AArch64BESysVVsnprintf(Vsnprintf, AArch64BESysVModel):
    pass


class AArch64BESysVVsprintf(Vsprintf, AArch64BESysVModel):
    pass


class AArch64BESysVVsscanf(Vsscanf, AArch64BESysVModel):
    pass


__all__ = [
    "AArch64BESysVPerror",
    "AArch64BESysVPrintfChk",
    "AArch64BESysVFprintfChk",
    "AArch64BESysVSnprintfChk",
    "AArch64BESysVSprintfChk",
    "AArch64BESysVFclose",
    "AArch64BESysVFeof",
    "AArch64BESysVFerror",
    "AArch64BESysVFgetc",
    "AArch64BESysVFgets",
    "AArch64BESysVFopen",
    "AArch64BESysVFprintf",
    "AArch64BESysVFputc",
    "AArch64BESysVFputs",
    "AArch64BESysVFread",
    "AArch64BESysVFscanf",
    "AArch64BESysVFseek",
    "AArch64BESysVFtell",
    "AArch64BESysVFwrite",
    "AArch64BESysVGetc",
    "AArch64BESysVGetchar",
    "AArch64BESysVGets",
    "AArch64BESysVPrintf",
    "AArch64BESysVPutc",
    "AArch64BESysVPutchar",
    "AArch64BESysVPuts",
    "AArch64BESysVRemove",
    "AArch64BESysVRename",
    "AArch64BESysVRewind",
    "AArch64BESysVScanf",
    "AArch64BESysVSnprintf",
    "AArch64BESysVSprintf",
    "AArch64BESysVSscanf",
    "AArch64BESysVClearerr",
    "AArch64BESysVFflush",
    "AArch64BESysVFreopen",
    "AArch64BESysVFgetpos",
    "AArch64BESysVFsetpos",
    "AArch64BESysVTmpfile",
    "AArch64BESysVTmpnam",
    "AArch64BESysVUngetc",
    "AArch64BESysVVfprintf",
    "AArch64BESysVVfscanf",
    "AArch64BESysVVprintf",
    "AArch64BESysVVscanf",
    "AArch64BESysVVsnprintf",
    "AArch64BESysVVsprintf",
    "AArch64BESysVVsscanf",
]
