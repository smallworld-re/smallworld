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
from ..systemv import RiscV32SysVModel


class RiscV32SysVPerror(Perror, RiscV32SysVModel):
    pass


class RiscV32SysVPrintfChk(PrintfChk, RiscV32SysVModel):
    pass


class RiscV32SysVFprintfChk(FprintfChk, RiscV32SysVModel):
    pass


class RiscV32SysVSnprintfChk(SnprintfChk, RiscV32SysVModel):
    pass


class RiscV32SysVSprintfChk(SprintfChk, RiscV32SysVModel):
    pass


class RiscV32SysVFclose(Fclose, RiscV32SysVModel):
    pass


class RiscV32SysVFeof(Feof, RiscV32SysVModel):
    pass


class RiscV32SysVFerror(Ferror, RiscV32SysVModel):
    pass


class RiscV32SysVFgetc(Fgetc, RiscV32SysVModel):
    pass


class RiscV32SysVFgets(Fgets, RiscV32SysVModel):
    pass


class RiscV32SysVFopen(Fopen, RiscV32SysVModel):
    pass


class RiscV32SysVFprintf(Fprintf, RiscV32SysVModel):
    pass


class RiscV32SysVFputc(Fputc, RiscV32SysVModel):
    pass


class RiscV32SysVFputs(Fputs, RiscV32SysVModel):
    pass


class RiscV32SysVFread(Fread, RiscV32SysVModel):
    pass


class RiscV32SysVFscanf(Fscanf, RiscV32SysVModel):
    pass


class RiscV32SysVFseek(Fseek, RiscV32SysVModel):
    pass


class RiscV32SysVFtell(Ftell, RiscV32SysVModel):
    pass


class RiscV32SysVFwrite(Fwrite, RiscV32SysVModel):
    pass


class RiscV32SysVGetc(Getc, RiscV32SysVModel):
    pass


class RiscV32SysVGetchar(Getchar, RiscV32SysVModel):
    pass


class RiscV32SysVGets(Gets, RiscV32SysVModel):
    pass


class RiscV32SysVPrintf(Printf, RiscV32SysVModel):
    pass


class RiscV32SysVPutc(Putc, RiscV32SysVModel):
    pass


class RiscV32SysVPutchar(Putchar, RiscV32SysVModel):
    pass


class RiscV32SysVPuts(Puts, RiscV32SysVModel):
    pass


class RiscV32SysVRemove(Remove, RiscV32SysVModel):
    pass


class RiscV32SysVRename(Rename, RiscV32SysVModel):
    pass


class RiscV32SysVRewind(Rewind, RiscV32SysVModel):
    pass


class RiscV32SysVScanf(Scanf, RiscV32SysVModel):
    pass


class RiscV32SysVSnprintf(Snprintf, RiscV32SysVModel):
    pass


class RiscV32SysVSprintf(Sprintf, RiscV32SysVModel):
    pass


class RiscV32SysVSscanf(Sscanf, RiscV32SysVModel):
    pass


class RiscV32SysVClearerr(Clearerr, RiscV32SysVModel):
    pass


class RiscV32SysVFflush(Fflush, RiscV32SysVModel):
    pass


class RiscV32SysVFreopen(Freopen, RiscV32SysVModel):
    pass


class RiscV32SysVFgetpos(Fgetpos, RiscV32SysVModel):
    pass


class RiscV32SysVFsetpos(Fsetpos, RiscV32SysVModel):
    pass


class RiscV32SysVTmpfile(Tmpfile, RiscV32SysVModel):
    pass


class RiscV32SysVTmpnam(Tmpnam, RiscV32SysVModel):
    pass


class RiscV32SysVUngetc(Ungetc, RiscV32SysVModel):
    pass


class RiscV32SysVVfprintf(Vfprintf, RiscV32SysVModel):
    pass


class RiscV32SysVVfscanf(Vfscanf, RiscV32SysVModel):
    pass


class RiscV32SysVVprintf(Vprintf, RiscV32SysVModel):
    pass


class RiscV32SysVVscanf(Vscanf, RiscV32SysVModel):
    pass


class RiscV32SysVVsnprintf(Vsnprintf, RiscV32SysVModel):
    pass


class RiscV32SysVVsprintf(Vsprintf, RiscV32SysVModel):
    pass


class RiscV32SysVVsscanf(Vsscanf, RiscV32SysVModel):
    pass


__all__ = [
    "RiscV32SysVPerror",
    "RiscV32SysVPrintfChk",
    "RiscV32SysVFprintfChk",
    "RiscV32SysVSnprintfChk",
    "RiscV32SysVSprintfChk",
    "RiscV32SysVFclose",
    "RiscV32SysVFeof",
    "RiscV32SysVFerror",
    "RiscV32SysVFgetc",
    "RiscV32SysVFgets",
    "RiscV32SysVFopen",
    "RiscV32SysVFprintf",
    "RiscV32SysVFputc",
    "RiscV32SysVFputs",
    "RiscV32SysVFread",
    "RiscV32SysVFscanf",
    "RiscV32SysVFseek",
    "RiscV32SysVFtell",
    "RiscV32SysVFwrite",
    "RiscV32SysVGetc",
    "RiscV32SysVGetchar",
    "RiscV32SysVGets",
    "RiscV32SysVPrintf",
    "RiscV32SysVPutc",
    "RiscV32SysVPutchar",
    "RiscV32SysVPuts",
    "RiscV32SysVRemove",
    "RiscV32SysVRename",
    "RiscV32SysVRewind",
    "RiscV32SysVScanf",
    "RiscV32SysVSnprintf",
    "RiscV32SysVSprintf",
    "RiscV32SysVSscanf",
    "RiscV32SysVClearerr",
    "RiscV32SysVFflush",
    "RiscV32SysVFreopen",
    "RiscV32SysVFgetpos",
    "RiscV32SysVFsetpos",
    "RiscV32SysVTmpfile",
    "RiscV32SysVTmpnam",
    "RiscV32SysVUngetc",
    "RiscV32SysVVfprintf",
    "RiscV32SysVVfscanf",
    "RiscV32SysVVprintf",
    "RiscV32SysVVscanf",
    "RiscV32SysVVsnprintf",
    "RiscV32SysVVsprintf",
    "RiscV32SysVVsscanf",
]
