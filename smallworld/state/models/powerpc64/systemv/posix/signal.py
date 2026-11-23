from ....posix.signal import (
    BsdSignal,
    Kill,
    Killpg,
    PthreadKill,
    PthreadSigmask,
    Sigaction,
    Sigaddset,
    Sigaltstack,
    Sigdelset,
    Sigemptyset,
    Sigfillset,
    Sighold,
    Sigignore,
    Siginterrupt,
    Sigismember,
    Sigpause,
    Sigpending,
    Sigprocmask,
    Sigqueue,
    Sigrelse,
    Sigset,
    Sigsuspend,
    Sigtimedwait,
    Sigwait,
    Sigwaitinfo,
)
from ..systemv import PowerPC64SysVModel


class PowerPC64SysVBsdSignal(BsdSignal, PowerPC64SysVModel):
    pass


class PowerPC64SysVKill(Kill, PowerPC64SysVModel):
    pass


class PowerPC64SysVKillpg(Killpg, PowerPC64SysVModel):
    pass


class PowerPC64SysVPthreadKill(PthreadKill, PowerPC64SysVModel):
    pass


class PowerPC64SysVPthreadSigmask(PthreadSigmask, PowerPC64SysVModel):
    pass


class PowerPC64SysVSigaction(Sigaction, PowerPC64SysVModel):
    pass


class PowerPC64SysVSigaddset(Sigaddset, PowerPC64SysVModel):
    pass


class PowerPC64SysVSigaltstack(Sigaltstack, PowerPC64SysVModel):
    pass


class PowerPC64SysVSigdelset(Sigdelset, PowerPC64SysVModel):
    pass


class PowerPC64SysVSigemptyset(Sigemptyset, PowerPC64SysVModel):
    pass


class PowerPC64SysVSigfillset(Sigfillset, PowerPC64SysVModel):
    pass


class PowerPC64SysVSighold(Sighold, PowerPC64SysVModel):
    pass


class PowerPC64SysVSigignore(Sigignore, PowerPC64SysVModel):
    pass


class PowerPC64SysVSiginterrupt(Siginterrupt, PowerPC64SysVModel):
    pass


class PowerPC64SysVSigismember(Sigismember, PowerPC64SysVModel):
    pass


class PowerPC64SysVSigpause(Sigpause, PowerPC64SysVModel):
    pass


class PowerPC64SysVSigpending(Sigpending, PowerPC64SysVModel):
    pass


class PowerPC64SysVSigprocmask(Sigprocmask, PowerPC64SysVModel):
    pass


class PowerPC64SysVSigqueue(Sigqueue, PowerPC64SysVModel):
    pass


class PowerPC64SysVSigrelse(Sigrelse, PowerPC64SysVModel):
    pass


class PowerPC64SysVSigset(Sigset, PowerPC64SysVModel):
    pass


class PowerPC64SysVSigsuspend(Sigsuspend, PowerPC64SysVModel):
    pass


class PowerPC64SysVSigtimedwait(Sigtimedwait, PowerPC64SysVModel):
    pass


class PowerPC64SysVSigwait(Sigwait, PowerPC64SysVModel):
    pass


class PowerPC64SysVSigwaitinfo(Sigwaitinfo, PowerPC64SysVModel):
    pass


__all__ = [
    "PowerPC64SysVBsdSignal",
    "PowerPC64SysVKill",
    "PowerPC64SysVKillpg",
    "PowerPC64SysVPthreadKill",
    "PowerPC64SysVPthreadSigmask",
    "PowerPC64SysVSigaction",
    "PowerPC64SysVSigaddset",
    "PowerPC64SysVSigaltstack",
    "PowerPC64SysVSigdelset",
    "PowerPC64SysVSigemptyset",
    "PowerPC64SysVSigfillset",
    "PowerPC64SysVSighold",
    "PowerPC64SysVSigignore",
    "PowerPC64SysVSiginterrupt",
    "PowerPC64SysVSigismember",
    "PowerPC64SysVSigpause",
    "PowerPC64SysVSigpending",
    "PowerPC64SysVSigprocmask",
    "PowerPC64SysVSigqueue",
    "PowerPC64SysVSigrelse",
    "PowerPC64SysVSigset",
    "PowerPC64SysVSigsuspend",
    "PowerPC64SysVSigtimedwait",
    "PowerPC64SysVSigwait",
    "PowerPC64SysVSigwaitinfo",
]
