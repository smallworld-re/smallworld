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
from ..systemv import PowerPCSysVModel


class PowerPCSysVBsdSignal(BsdSignal, PowerPCSysVModel):
    pass


class PowerPCSysVKill(Kill, PowerPCSysVModel):
    pass


class PowerPCSysVKillpg(Killpg, PowerPCSysVModel):
    pass


class PowerPCSysVPthreadKill(PthreadKill, PowerPCSysVModel):
    pass


class PowerPCSysVPthreadSigmask(PthreadSigmask, PowerPCSysVModel):
    pass


class PowerPCSysVSigaction(Sigaction, PowerPCSysVModel):
    pass


class PowerPCSysVSigaddset(Sigaddset, PowerPCSysVModel):
    pass


class PowerPCSysVSigaltstack(Sigaltstack, PowerPCSysVModel):
    pass


class PowerPCSysVSigdelset(Sigdelset, PowerPCSysVModel):
    pass


class PowerPCSysVSigemptyset(Sigemptyset, PowerPCSysVModel):
    pass


class PowerPCSysVSigfillset(Sigfillset, PowerPCSysVModel):
    pass


class PowerPCSysVSighold(Sighold, PowerPCSysVModel):
    pass


class PowerPCSysVSigignore(Sigignore, PowerPCSysVModel):
    pass


class PowerPCSysVSiginterrupt(Siginterrupt, PowerPCSysVModel):
    pass


class PowerPCSysVSigismember(Sigismember, PowerPCSysVModel):
    pass


class PowerPCSysVSigpause(Sigpause, PowerPCSysVModel):
    pass


class PowerPCSysVSigpending(Sigpending, PowerPCSysVModel):
    pass


class PowerPCSysVSigprocmask(Sigprocmask, PowerPCSysVModel):
    pass


class PowerPCSysVSigqueue(Sigqueue, PowerPCSysVModel):
    pass


class PowerPCSysVSigrelse(Sigrelse, PowerPCSysVModel):
    pass


class PowerPCSysVSigset(Sigset, PowerPCSysVModel):
    pass


class PowerPCSysVSigsuspend(Sigsuspend, PowerPCSysVModel):
    pass


class PowerPCSysVSigtimedwait(Sigtimedwait, PowerPCSysVModel):
    pass


class PowerPCSysVSigwait(Sigwait, PowerPCSysVModel):
    pass


class PowerPCSysVSigwaitinfo(Sigwaitinfo, PowerPCSysVModel):
    pass


__all__ = [
    "PowerPCSysVBsdSignal",
    "PowerPCSysVKill",
    "PowerPCSysVKillpg",
    "PowerPCSysVPthreadKill",
    "PowerPCSysVPthreadSigmask",
    "PowerPCSysVSigaction",
    "PowerPCSysVSigaddset",
    "PowerPCSysVSigaltstack",
    "PowerPCSysVSigdelset",
    "PowerPCSysVSigemptyset",
    "PowerPCSysVSigfillset",
    "PowerPCSysVSighold",
    "PowerPCSysVSigignore",
    "PowerPCSysVSiginterrupt",
    "PowerPCSysVSigismember",
    "PowerPCSysVSigpause",
    "PowerPCSysVSigpending",
    "PowerPCSysVSigprocmask",
    "PowerPCSysVSigqueue",
    "PowerPCSysVSigrelse",
    "PowerPCSysVSigset",
    "PowerPCSysVSigsuspend",
    "PowerPCSysVSigtimedwait",
    "PowerPCSysVSigwait",
    "PowerPCSysVSigwaitinfo",
]
