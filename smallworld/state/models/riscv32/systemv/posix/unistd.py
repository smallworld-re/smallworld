from ....cstd import ArgumentType
from ....posix.unistd import (
    Access,
    Alarm,
    Brk,
    Chdir,
    Chown,
    Chroot,
    Close,
    Confstr,
    Crypt,
    Ctermid,
    Cuserid,
    Dup,
    Dup2,
    Encrypt,
    ErrnoLocation,
    Execl,
    Execle,
    Execlp,
    Execv,
    Execve,
    Execvp,
    Fchdir,
    Fchown,
    Fdatasync,
    Fork,
    Fpathconf,
    Fsync,
    Ftruncate,
    Getcwd,
    Getegid,
    Geteuid,
    Getgid,
    Getgroups,
    Gethostid,
    Getlogin,
    GetloginR,
    Getopt,
    Getpgid,
    Getpgrp,
    Getpid,
    Getppid,
    Getsid,
    Getuid,
    Getwd,
    Isatty,
    Lchown,
    Link,
    Lockf,
    Lseek,
    Nice,
    Pathconf,
    Pause,
    Pipe,
    Pread,
    PthreadAtfork,
    Pwrite,
    Read,
    Readlink,
    Rmdir,
    Sbrk,
    Setegid,
    Seteuid,
    Setgid,
    Setpgid,
    Setpgrp,
    Setregid,
    Setreuid,
    Setsid,
    Sleep,
    Swab,
    Symlink,
    Sync,
    Sysconf,
    Tcgetpgrp,
    TCsetpgrp,
    Truncate,
    Ttyname,
    TtynameR,
    Ularm,
    Unlink,
    Usleep,
    Vfork,
    Write,
)
from ..systemv import RiscV32SysVModel


class RiscV32SysVErrnoLocation(ErrnoLocation, RiscV32SysVModel):
    pass


class RiscV32SysVAccess(Access, RiscV32SysVModel):
    pass


class RiscV32SysVAlarm(Alarm, RiscV32SysVModel):
    pass


class RiscV32SysVBrk(Brk, RiscV32SysVModel):
    pass


class RiscV32SysVChdir(Chdir, RiscV32SysVModel):
    pass


class RiscV32SysVChroot(Chroot, RiscV32SysVModel):
    pass


class RiscV32SysVChown(Chown, RiscV32SysVModel):
    pass


class RiscV32SysVClose(Close, RiscV32SysVModel):
    pass


class RiscV32SysVConfstr(Confstr, RiscV32SysVModel):
    pass


class RiscV32SysVCrypt(Crypt, RiscV32SysVModel):
    pass


class RiscV32SysVCtermid(Ctermid, RiscV32SysVModel):
    pass


class RiscV32SysVCuserid(Cuserid, RiscV32SysVModel):
    pass


class RiscV32SysVDup(Dup, RiscV32SysVModel):
    pass


class RiscV32SysVDup2(Dup2, RiscV32SysVModel):
    pass


class RiscV32SysVEncrypt(Encrypt, RiscV32SysVModel):
    pass


class RiscV32SysVExecl(Execl, RiscV32SysVModel):
    pass


class RiscV32SysVExecle(Execle, RiscV32SysVModel):
    pass


class RiscV32SysVExeclp(Execlp, RiscV32SysVModel):
    pass


class RiscV32SysVExecv(Execv, RiscV32SysVModel):
    pass


class RiscV32SysVExecvp(Execvp, RiscV32SysVModel):
    pass


class RiscV32SysVExecve(Execve, RiscV32SysVModel):
    pass


class RiscV32SysVFchown(Fchown, RiscV32SysVModel):
    pass


class RiscV32SysVFchdir(Fchdir, RiscV32SysVModel):
    pass


class RiscV32SysVFdatasync(Fdatasync, RiscV32SysVModel):
    pass


class RiscV32SysVFork(Fork, RiscV32SysVModel):
    pass


class RiscV32SysVFpathconf(Fpathconf, RiscV32SysVModel):
    pass


class RiscV32SysVFsync(Fsync, RiscV32SysVModel):
    pass


class RiscV32SysVFtruncate(Ftruncate, RiscV32SysVModel):
    # glibc gave RiscV32 a 64-bit off_t from the start.
    argument_types = [ArgumentType.INT, ArgumentType.LONGLONG]


class RiscV32SysVGetcwd(Getcwd, RiscV32SysVModel):
    pass


class RiscV32SysVGetegid(Getegid, RiscV32SysVModel):
    pass


class RiscV32SysVGeteuid(Geteuid, RiscV32SysVModel):
    pass


class RiscV32SysVGetgid(Getgid, RiscV32SysVModel):
    pass


class RiscV32SysVGetgroups(Getgroups, RiscV32SysVModel):
    pass


class RiscV32SysVGethostid(Gethostid, RiscV32SysVModel):
    pass


class RiscV32SysVGetlogin(Getlogin, RiscV32SysVModel):
    pass


class RiscV32SysVGetloginR(GetloginR, RiscV32SysVModel):
    pass


class RiscV32SysVGetopt(Getopt, RiscV32SysVModel):
    pass


class RiscV32SysVGetpgid(Getpgid, RiscV32SysVModel):
    pass


class RiscV32SysVGetpgrp(Getpgrp, RiscV32SysVModel):
    pass


class RiscV32SysVGetpid(Getpid, RiscV32SysVModel):
    pass


class RiscV32SysVGetppid(Getppid, RiscV32SysVModel):
    pass


class RiscV32SysVGetsid(Getsid, RiscV32SysVModel):
    pass


class RiscV32SysVGetuid(Getuid, RiscV32SysVModel):
    pass


class RiscV32SysVGetwd(Getwd, RiscV32SysVModel):
    pass


class RiscV32SysVIsatty(Isatty, RiscV32SysVModel):
    pass


class RiscV32SysVLchown(Lchown, RiscV32SysVModel):
    pass


class RiscV32SysVLink(Link, RiscV32SysVModel):
    pass


class RiscV32SysVLockf(Lockf, RiscV32SysVModel):
    # glibc gave RiscV32 a 64-bit off_t from the start.
    argument_types = [ArgumentType.INT, ArgumentType.INT, ArgumentType.LONGLONG]


class RiscV32SysVLseek(Lseek, RiscV32SysVModel):
    # glibc gave RiscV32 a 64-bit off_t from the start.
    argument_types = [ArgumentType.INT, ArgumentType.LONGLONG, ArgumentType.INT]
    return_type = ArgumentType.LONGLONG


class RiscV32SysVNice(Nice, RiscV32SysVModel):
    pass


class RiscV32SysVPathconf(Pathconf, RiscV32SysVModel):
    pass


class RiscV32SysVPause(Pause, RiscV32SysVModel):
    pass


class RiscV32SysVPipe(Pipe, RiscV32SysVModel):
    pass


class RiscV32SysVPread(Pread, RiscV32SysVModel):
    # glibc gave RiscV32 a 64-bit off_t from the start.
    argument_types = [
        ArgumentType.INT,
        ArgumentType.POINTER,
        ArgumentType.SIZE_T,
        ArgumentType.LONGLONG,
    ]


class RiscV32SysVPthreadAtfork(PthreadAtfork, RiscV32SysVModel):
    pass


class RiscV32SysVPwrite(Pwrite, RiscV32SysVModel):
    # glibc gave RiscV32 a 64-bit off_t from the start.
    argument_types = [
        ArgumentType.INT,
        ArgumentType.POINTER,
        ArgumentType.SIZE_T,
        ArgumentType.LONGLONG,
    ]


class RiscV32SysVRead(Read, RiscV32SysVModel):
    pass


class RiscV32SysVReadlink(Readlink, RiscV32SysVModel):
    pass


class RiscV32SysVRmdir(Rmdir, RiscV32SysVModel):
    pass


class RiscV32SysVSbrk(Sbrk, RiscV32SysVModel):
    pass


class RiscV32SysVSetegid(Setegid, RiscV32SysVModel):
    pass


class RiscV32SysVSeteuid(Seteuid, RiscV32SysVModel):
    pass


class RiscV32SysVSetgid(Setgid, RiscV32SysVModel):
    pass


class RiscV32SysVSetpgid(Setpgid, RiscV32SysVModel):
    pass


class RiscV32SysVSetpgrp(Setpgrp, RiscV32SysVModel):
    pass


class RiscV32SysVSetregid(Setregid, RiscV32SysVModel):
    pass


class RiscV32SysVSetreuid(Setreuid, RiscV32SysVModel):
    pass


class RiscV32SysVSetsid(Setsid, RiscV32SysVModel):
    pass


class RiscV32SysVSleep(Sleep, RiscV32SysVModel):
    pass


class RiscV32SysVSwab(Swab, RiscV32SysVModel):
    pass


class RiscV32SysVSymlink(Symlink, RiscV32SysVModel):
    pass


class RiscV32SysVSync(Sync, RiscV32SysVModel):
    pass


class RiscV32SysVSysconf(Sysconf, RiscV32SysVModel):
    pass


class RiscV32SysVTcgetpgrp(Tcgetpgrp, RiscV32SysVModel):
    pass


class RiscV32SysVTCsetpgrp(TCsetpgrp, RiscV32SysVModel):
    pass


class RiscV32SysVTruncate(Truncate, RiscV32SysVModel):
    # glibc gave RiscV32 a 64-bit off_t from the start.
    argument_types = [ArgumentType.POINTER, ArgumentType.LONGLONG]


class RiscV32SysVTtyname(Ttyname, RiscV32SysVModel):
    pass


class RiscV32SysVTtynameR(TtynameR, RiscV32SysVModel):
    pass


class RiscV32SysVUlarm(Ularm, RiscV32SysVModel):
    pass


class RiscV32SysVUnlink(Unlink, RiscV32SysVModel):
    pass


class RiscV32SysVUsleep(Usleep, RiscV32SysVModel):
    pass


class RiscV32SysVVfork(Vfork, RiscV32SysVModel):
    pass


class RiscV32SysVWrite(Write, RiscV32SysVModel):
    pass


__all__ = [
    "RiscV32SysVErrnoLocation",
    "RiscV32SysVAccess",
    "RiscV32SysVAlarm",
    "RiscV32SysVBrk",
    "RiscV32SysVChdir",
    "RiscV32SysVChroot",
    "RiscV32SysVChown",
    "RiscV32SysVClose",
    "RiscV32SysVConfstr",
    "RiscV32SysVCrypt",
    "RiscV32SysVCtermid",
    "RiscV32SysVCuserid",
    "RiscV32SysVDup",
    "RiscV32SysVDup2",
    "RiscV32SysVEncrypt",
    "RiscV32SysVExecl",
    "RiscV32SysVExecle",
    "RiscV32SysVExeclp",
    "RiscV32SysVExecv",
    "RiscV32SysVExecvp",
    "RiscV32SysVExecve",
    "RiscV32SysVFchown",
    "RiscV32SysVFchdir",
    "RiscV32SysVFdatasync",
    "RiscV32SysVFork",
    "RiscV32SysVFpathconf",
    "RiscV32SysVFsync",
    "RiscV32SysVFtruncate",
    "RiscV32SysVGetcwd",
    "RiscV32SysVGetegid",
    "RiscV32SysVGeteuid",
    "RiscV32SysVGetgid",
    "RiscV32SysVGetgroups",
    "RiscV32SysVGethostid",
    "RiscV32SysVGetlogin",
    "RiscV32SysVGetloginR",
    "RiscV32SysVGetopt",
    "RiscV32SysVGetpgid",
    "RiscV32SysVGetpgrp",
    "RiscV32SysVGetpid",
    "RiscV32SysVGetppid",
    "RiscV32SysVGetsid",
    "RiscV32SysVGetuid",
    "RiscV32SysVGetwd",
    "RiscV32SysVIsatty",
    "RiscV32SysVLchown",
    "RiscV32SysVLink",
    "RiscV32SysVLockf",
    "RiscV32SysVLseek",
    "RiscV32SysVNice",
    "RiscV32SysVPathconf",
    "RiscV32SysVPause",
    "RiscV32SysVPipe",
    "RiscV32SysVPread",
    "RiscV32SysVPthreadAtfork",
    "RiscV32SysVPwrite",
    "RiscV32SysVRead",
    "RiscV32SysVReadlink",
    "RiscV32SysVRmdir",
    "RiscV32SysVSbrk",
    "RiscV32SysVSetegid",
    "RiscV32SysVSeteuid",
    "RiscV32SysVSetgid",
    "RiscV32SysVSetpgid",
    "RiscV32SysVSetpgrp",
    "RiscV32SysVSetregid",
    "RiscV32SysVSetreuid",
    "RiscV32SysVSetsid",
    "RiscV32SysVSleep",
    "RiscV32SysVSwab",
    "RiscV32SysVSymlink",
    "RiscV32SysVSync",
    "RiscV32SysVSysconf",
    "RiscV32SysVTcgetpgrp",
    "RiscV32SysVTCsetpgrp",
    "RiscV32SysVTruncate",
    "RiscV32SysVTtyname",
    "RiscV32SysVTtynameR",
    "RiscV32SysVUlarm",
    "RiscV32SysVUnlink",
    "RiscV32SysVUsleep",
    "RiscV32SysVVfork",
    "RiscV32SysVWrite",
]
