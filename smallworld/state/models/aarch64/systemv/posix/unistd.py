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
from ..systemv import AArch64SysVModel


class AArch64SysVAccess(Access, AArch64SysVModel):
    pass


class AArch64SysVAlarm(Alarm, AArch64SysVModel):
    pass


class AArch64SysVBrk(Brk, AArch64SysVModel):
    pass


class AArch64SysVChdir(Chdir, AArch64SysVModel):
    pass


class AArch64SysVChroot(Chroot, AArch64SysVModel):
    pass


class AArch64SysVChown(Chown, AArch64SysVModel):
    pass


class AArch64SysVClose(Close, AArch64SysVModel):
    pass


class AArch64SysVConfstr(Confstr, AArch64SysVModel):
    pass


class AArch64SysVCrypt(Crypt, AArch64SysVModel):
    pass


class AArch64SysVCtermid(Ctermid, AArch64SysVModel):
    pass


class AArch64SysVCuserid(Cuserid, AArch64SysVModel):
    pass


class AArch64SysVDup(Dup, AArch64SysVModel):
    pass


class AArch64SysVDup2(Dup2, AArch64SysVModel):
    pass


class AArch64SysVEncrypt(Encrypt, AArch64SysVModel):
    pass


class AArch64SysVExecl(Execl, AArch64SysVModel):
    pass


class AArch64SysVExecle(Execle, AArch64SysVModel):
    pass


class AArch64SysVExeclp(Execlp, AArch64SysVModel):
    pass


class AArch64SysVExecv(Execv, AArch64SysVModel):
    pass


class AArch64SysVExecvp(Execvp, AArch64SysVModel):
    pass


class AArch64SysVExecve(Execve, AArch64SysVModel):
    pass


class AArch64SysVFchown(Fchown, AArch64SysVModel):
    pass


class AArch64SysVFchdir(Fchdir, AArch64SysVModel):
    pass


class AArch64SysVFdatasync(Fdatasync, AArch64SysVModel):
    pass


class AArch64SysVFork(Fork, AArch64SysVModel):
    pass


class AArch64SysVFpathconf(Fpathconf, AArch64SysVModel):
    pass


class AArch64SysVFsync(Fsync, AArch64SysVModel):
    pass


class AArch64SysVFtruncate(Ftruncate, AArch64SysVModel):
    pass


class AArch64SysVGetcwd(Getcwd, AArch64SysVModel):
    pass


class AArch64SysVGetegid(Getegid, AArch64SysVModel):
    pass


class AArch64SysVGeteuid(Geteuid, AArch64SysVModel):
    pass


class AArch64SysVGetgid(Getgid, AArch64SysVModel):
    pass


class AArch64SysVGetgroups(Getgroups, AArch64SysVModel):
    pass


class AArch64SysVGethostid(Gethostid, AArch64SysVModel):
    pass


class AArch64SysVGetlogin(Getlogin, AArch64SysVModel):
    pass


class AArch64SysVGetloginR(GetloginR, AArch64SysVModel):
    pass


class AArch64SysVGetopt(Getopt, AArch64SysVModel):
    pass


class AArch64SysVGetpgid(Getpgid, AArch64SysVModel):
    pass


class AArch64SysVGetpgrp(Getpgrp, AArch64SysVModel):
    pass


class AArch64SysVGetpid(Getpid, AArch64SysVModel):
    pass


class AArch64SysVGetppid(Getppid, AArch64SysVModel):
    pass


class AArch64SysVGetsid(Getsid, AArch64SysVModel):
    pass


class AArch64SysVGetuid(Getuid, AArch64SysVModel):
    pass


class AArch64SysVGetwd(Getwd, AArch64SysVModel):
    pass


class AArch64SysVIsatty(Isatty, AArch64SysVModel):
    pass


class AArch64SysVLchown(Lchown, AArch64SysVModel):
    pass


class AArch64SysVLink(Link, AArch64SysVModel):
    pass


class AArch64SysVLockf(Lockf, AArch64SysVModel):
    pass


class AArch64SysVLseek(Lseek, AArch64SysVModel):
    pass


class AArch64SysVNice(Nice, AArch64SysVModel):
    pass


class AArch64SysVPathconf(Pathconf, AArch64SysVModel):
    pass


class AArch64SysVPause(Pause, AArch64SysVModel):
    pass


class AArch64SysVPipe(Pipe, AArch64SysVModel):
    pass


class AArch64SysVPread(Pread, AArch64SysVModel):
    pass


class AArch64SysVPthreadAtfork(PthreadAtfork, AArch64SysVModel):
    pass


class AArch64SysVPwrite(Pwrite, AArch64SysVModel):
    pass


class AArch64SysVRead(Read, AArch64SysVModel):
    pass


class AArch64SysVReadlink(Readlink, AArch64SysVModel):
    pass


class AArch64SysVRmdir(Rmdir, AArch64SysVModel):
    pass


class AArch64SysVSbrk(Sbrk, AArch64SysVModel):
    pass


class AArch64SysVSetegid(Setegid, AArch64SysVModel):
    pass


class AArch64SysVSeteuid(Seteuid, AArch64SysVModel):
    pass


class AArch64SysVSetgid(Setgid, AArch64SysVModel):
    pass


class AArch64SysVSetpgid(Setpgid, AArch64SysVModel):
    pass


class AArch64SysVSetpgrp(Setpgrp, AArch64SysVModel):
    pass


class AArch64SysVSetregid(Setregid, AArch64SysVModel):
    pass


class AArch64SysVSetreuid(Setreuid, AArch64SysVModel):
    pass


class AArch64SysVSetsid(Setsid, AArch64SysVModel):
    pass


class AArch64SysVSleep(Sleep, AArch64SysVModel):
    pass


class AArch64SysVSwab(Swab, AArch64SysVModel):
    pass


class AArch64SysVSymlink(Symlink, AArch64SysVModel):
    pass


class AArch64SysVSync(Sync, AArch64SysVModel):
    pass


class AArch64SysVSysconf(Sysconf, AArch64SysVModel):
    pass


class AArch64SysVTcgetpgrp(Tcgetpgrp, AArch64SysVModel):
    pass


class AArch64SysVTCsetpgrp(TCsetpgrp, AArch64SysVModel):
    pass


class AArch64SysVTruncate(Truncate, AArch64SysVModel):
    pass


class AArch64SysVTtyname(Ttyname, AArch64SysVModel):
    pass


class AArch64SysVTtynameR(TtynameR, AArch64SysVModel):
    pass


class AArch64SysVUlarm(Ularm, AArch64SysVModel):
    pass


class AArch64SysVUnlink(Unlink, AArch64SysVModel):
    pass


class AArch64SysVUsleep(Usleep, AArch64SysVModel):
    pass


class AArch64SysVVfork(Vfork, AArch64SysVModel):
    pass


class AArch64SysVWrite(Write, AArch64SysVModel):
    pass


__all__ = [
    "AArch64SysVAccess",
    "AArch64SysVAlarm",
    "AArch64SysVBrk",
    "AArch64SysVChdir",
    "AArch64SysVChroot",
    "AArch64SysVChown",
    "AArch64SysVClose",
    "AArch64SysVConfstr",
    "AArch64SysVCrypt",
    "AArch64SysVCtermid",
    "AArch64SysVCuserid",
    "AArch64SysVDup",
    "AArch64SysVDup2",
    "AArch64SysVEncrypt",
    "AArch64SysVExecl",
    "AArch64SysVExecle",
    "AArch64SysVExeclp",
    "AArch64SysVExecv",
    "AArch64SysVExecvp",
    "AArch64SysVExecve",
    "AArch64SysVFchown",
    "AArch64SysVFchdir",
    "AArch64SysVFdatasync",
    "AArch64SysVFork",
    "AArch64SysVFpathconf",
    "AArch64SysVFsync",
    "AArch64SysVFtruncate",
    "AArch64SysVGetcwd",
    "AArch64SysVGetegid",
    "AArch64SysVGeteuid",
    "AArch64SysVGetgid",
    "AArch64SysVGetgroups",
    "AArch64SysVGethostid",
    "AArch64SysVGetlogin",
    "AArch64SysVGetloginR",
    "AArch64SysVGetopt",
    "AArch64SysVGetpgid",
    "AArch64SysVGetpgrp",
    "AArch64SysVGetpid",
    "AArch64SysVGetppid",
    "AArch64SysVGetsid",
    "AArch64SysVGetuid",
    "AArch64SysVGetwd",
    "AArch64SysVIsatty",
    "AArch64SysVLchown",
    "AArch64SysVLink",
    "AArch64SysVLockf",
    "AArch64SysVLseek",
    "AArch64SysVNice",
    "AArch64SysVPathconf",
    "AArch64SysVPause",
    "AArch64SysVPipe",
    "AArch64SysVPread",
    "AArch64SysVPthreadAtfork",
    "AArch64SysVPwrite",
    "AArch64SysVRead",
    "AArch64SysVReadlink",
    "AArch64SysVRmdir",
    "AArch64SysVSbrk",
    "AArch64SysVSetegid",
    "AArch64SysVSeteuid",
    "AArch64SysVSetgid",
    "AArch64SysVSetpgid",
    "AArch64SysVSetpgrp",
    "AArch64SysVSetregid",
    "AArch64SysVSetreuid",
    "AArch64SysVSetsid",
    "AArch64SysVSleep",
    "AArch64SysVSwab",
    "AArch64SysVSymlink",
    "AArch64SysVSync",
    "AArch64SysVSysconf",
    "AArch64SysVTcgetpgrp",
    "AArch64SysVTCsetpgrp",
    "AArch64SysVTruncate",
    "AArch64SysVTtyname",
    "AArch64SysVTtynameR",
    "AArch64SysVUlarm",
    "AArch64SysVUnlink",
    "AArch64SysVUsleep",
    "AArch64SysVVfork",
    "AArch64SysVWrite",
]
