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
from ..systemv import ArmELSysVModel


class ArmELSysVAccess(Access, ArmELSysVModel):
    pass


class ArmELSysVAlarm(Alarm, ArmELSysVModel):
    pass


class ArmELSysVBrk(Brk, ArmELSysVModel):
    pass


class ArmELSysVChdir(Chdir, ArmELSysVModel):
    pass


class ArmELSysVChroot(Chroot, ArmELSysVModel):
    pass


class ArmELSysVChown(Chown, ArmELSysVModel):
    pass


class ArmELSysVClose(Close, ArmELSysVModel):
    pass


class ArmELSysVConfstr(Confstr, ArmELSysVModel):
    pass


class ArmELSysVCrypt(Crypt, ArmELSysVModel):
    pass


class ArmELSysVCtermid(Ctermid, ArmELSysVModel):
    pass


class ArmELSysVCuserid(Cuserid, ArmELSysVModel):
    pass


class ArmELSysVDup(Dup, ArmELSysVModel):
    pass


class ArmELSysVDup2(Dup2, ArmELSysVModel):
    pass


class ArmELSysVEncrypt(Encrypt, ArmELSysVModel):
    pass


class ArmELSysVExecl(Execl, ArmELSysVModel):
    pass


class ArmELSysVExecle(Execle, ArmELSysVModel):
    pass


class ArmELSysVExeclp(Execlp, ArmELSysVModel):
    pass


class ArmELSysVExecv(Execv, ArmELSysVModel):
    pass


class ArmELSysVExecvp(Execvp, ArmELSysVModel):
    pass


class ArmELSysVExecve(Execve, ArmELSysVModel):
    pass


class ArmELSysVFchown(Fchown, ArmELSysVModel):
    pass


class ArmELSysVFchdir(Fchdir, ArmELSysVModel):
    pass


class ArmELSysVFdatasync(Fdatasync, ArmELSysVModel):
    pass


class ArmELSysVFork(Fork, ArmELSysVModel):
    pass


class ArmELSysVFpathconf(Fpathconf, ArmELSysVModel):
    pass


class ArmELSysVFsync(Fsync, ArmELSysVModel):
    pass


class ArmELSysVFtruncate(Ftruncate, ArmELSysVModel):
    pass


class ArmELSysVGetcwd(Getcwd, ArmELSysVModel):
    pass


class ArmELSysVGetegid(Getegid, ArmELSysVModel):
    pass


class ArmELSysVGeteuid(Geteuid, ArmELSysVModel):
    pass


class ArmELSysVGetgid(Getgid, ArmELSysVModel):
    pass


class ArmELSysVGetgroups(Getgroups, ArmELSysVModel):
    pass


class ArmELSysVGethostid(Gethostid, ArmELSysVModel):
    pass


class ArmELSysVGetlogin(Getlogin, ArmELSysVModel):
    pass


class ArmELSysVGetloginR(GetloginR, ArmELSysVModel):
    pass


class ArmELSysVGetopt(Getopt, ArmELSysVModel):
    pass


class ArmELSysVGetpgid(Getpgid, ArmELSysVModel):
    pass


class ArmELSysVGetpgrp(Getpgrp, ArmELSysVModel):
    pass


class ArmELSysVGetpid(Getpid, ArmELSysVModel):
    pass


class ArmELSysVGetppid(Getppid, ArmELSysVModel):
    pass


class ArmELSysVGetsid(Getsid, ArmELSysVModel):
    pass


class ArmELSysVGetuid(Getuid, ArmELSysVModel):
    pass


class ArmELSysVGetwd(Getwd, ArmELSysVModel):
    pass


class ArmELSysVIsatty(Isatty, ArmELSysVModel):
    pass


class ArmELSysVLchown(Lchown, ArmELSysVModel):
    pass


class ArmELSysVLink(Link, ArmELSysVModel):
    pass


class ArmELSysVLockf(Lockf, ArmELSysVModel):
    pass


class ArmELSysVLseek(Lseek, ArmELSysVModel):
    pass


class ArmELSysVNice(Nice, ArmELSysVModel):
    pass


class ArmELSysVPathconf(Pathconf, ArmELSysVModel):
    pass


class ArmELSysVPause(Pause, ArmELSysVModel):
    pass


class ArmELSysVPipe(Pipe, ArmELSysVModel):
    pass


class ArmELSysVPread(Pread, ArmELSysVModel):
    pass


class ArmELSysVPthreadAtfork(PthreadAtfork, ArmELSysVModel):
    pass


class ArmELSysVPwrite(Pwrite, ArmELSysVModel):
    pass


class ArmELSysVRead(Read, ArmELSysVModel):
    pass


class ArmELSysVReadlink(Readlink, ArmELSysVModel):
    pass


class ArmELSysVRmdir(Rmdir, ArmELSysVModel):
    pass


class ArmELSysVSbrk(Sbrk, ArmELSysVModel):
    pass


class ArmELSysVSetegid(Setegid, ArmELSysVModel):
    pass


class ArmELSysVSeteuid(Seteuid, ArmELSysVModel):
    pass


class ArmELSysVSetgid(Setgid, ArmELSysVModel):
    pass


class ArmELSysVSetpgid(Setpgid, ArmELSysVModel):
    pass


class ArmELSysVSetpgrp(Setpgrp, ArmELSysVModel):
    pass


class ArmELSysVSetregid(Setregid, ArmELSysVModel):
    pass


class ArmELSysVSetreuid(Setreuid, ArmELSysVModel):
    pass


class ArmELSysVSetsid(Setsid, ArmELSysVModel):
    pass


class ArmELSysVSleep(Sleep, ArmELSysVModel):
    pass


class ArmELSysVSwab(Swab, ArmELSysVModel):
    pass


class ArmELSysVSymlink(Symlink, ArmELSysVModel):
    pass


class ArmELSysVSync(Sync, ArmELSysVModel):
    pass


class ArmELSysVSysconf(Sysconf, ArmELSysVModel):
    pass


class ArmELSysVTcgetpgrp(Tcgetpgrp, ArmELSysVModel):
    pass


class ArmELSysVTCsetpgrp(TCsetpgrp, ArmELSysVModel):
    pass


class ArmELSysVTruncate(Truncate, ArmELSysVModel):
    pass


class ArmELSysVTtyname(Ttyname, ArmELSysVModel):
    pass


class ArmELSysVTtynameR(TtynameR, ArmELSysVModel):
    pass


class ArmELSysVUlarm(Ularm, ArmELSysVModel):
    pass


class ArmELSysVUnlink(Unlink, ArmELSysVModel):
    pass


class ArmELSysVUsleep(Usleep, ArmELSysVModel):
    pass


class ArmELSysVVfork(Vfork, ArmELSysVModel):
    pass


class ArmELSysVWrite(Write, ArmELSysVModel):
    pass


__all__ = [
    "ArmELSysVAccess",
    "ArmELSysVAlarm",
    "ArmELSysVBrk",
    "ArmELSysVChdir",
    "ArmELSysVChroot",
    "ArmELSysVChown",
    "ArmELSysVClose",
    "ArmELSysVConfstr",
    "ArmELSysVCrypt",
    "ArmELSysVCtermid",
    "ArmELSysVCuserid",
    "ArmELSysVDup",
    "ArmELSysVDup2",
    "ArmELSysVEncrypt",
    "ArmELSysVExecl",
    "ArmELSysVExecle",
    "ArmELSysVExeclp",
    "ArmELSysVExecv",
    "ArmELSysVExecvp",
    "ArmELSysVExecve",
    "ArmELSysVFchown",
    "ArmELSysVFchdir",
    "ArmELSysVFdatasync",
    "ArmELSysVFork",
    "ArmELSysVFpathconf",
    "ArmELSysVFsync",
    "ArmELSysVFtruncate",
    "ArmELSysVGetcwd",
    "ArmELSysVGetegid",
    "ArmELSysVGeteuid",
    "ArmELSysVGetgid",
    "ArmELSysVGetgroups",
    "ArmELSysVGethostid",
    "ArmELSysVGetlogin",
    "ArmELSysVGetloginR",
    "ArmELSysVGetopt",
    "ArmELSysVGetpgid",
    "ArmELSysVGetpgrp",
    "ArmELSysVGetpid",
    "ArmELSysVGetppid",
    "ArmELSysVGetsid",
    "ArmELSysVGetuid",
    "ArmELSysVGetwd",
    "ArmELSysVIsatty",
    "ArmELSysVLchown",
    "ArmELSysVLink",
    "ArmELSysVLockf",
    "ArmELSysVLseek",
    "ArmELSysVNice",
    "ArmELSysVPathconf",
    "ArmELSysVPause",
    "ArmELSysVPipe",
    "ArmELSysVPread",
    "ArmELSysVPthreadAtfork",
    "ArmELSysVPwrite",
    "ArmELSysVRead",
    "ArmELSysVReadlink",
    "ArmELSysVRmdir",
    "ArmELSysVSbrk",
    "ArmELSysVSetegid",
    "ArmELSysVSeteuid",
    "ArmELSysVSetgid",
    "ArmELSysVSetpgid",
    "ArmELSysVSetpgrp",
    "ArmELSysVSetregid",
    "ArmELSysVSetreuid",
    "ArmELSysVSetsid",
    "ArmELSysVSleep",
    "ArmELSysVSwab",
    "ArmELSysVSymlink",
    "ArmELSysVSync",
    "ArmELSysVSysconf",
    "ArmELSysVTcgetpgrp",
    "ArmELSysVTCsetpgrp",
    "ArmELSysVTruncate",
    "ArmELSysVTtyname",
    "ArmELSysVTtynameR",
    "ArmELSysVUlarm",
    "ArmELSysVUnlink",
    "ArmELSysVUsleep",
    "ArmELSysVVfork",
    "ArmELSysVWrite",
]
