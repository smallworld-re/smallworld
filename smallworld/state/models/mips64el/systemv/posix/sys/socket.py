from .....posix.socket import (
    Accept,
    Bind,
    Connect,
    Getpeername,
    Getsockname,
    Getsockopt,
    Listen,
    Recv,
    Recvfrom,
    Recvmsg,
    Send,
    Sendmsg,
    Sendto,
    Setsockopt,
    Shutdown,
    Socket,
    Socketpair,
)
from ...systemv import MIPS64ELSysVModel


class MIPS64ELSysVAccept(Accept, MIPS64ELSysVModel):
    pass


class MIPS64ELSysVBind(Bind, MIPS64ELSysVModel):
    pass


class MIPS64ELSysVConnect(Connect, MIPS64ELSysVModel):
    pass


class MIPS64ELSysVGetpeername(Getpeername, MIPS64ELSysVModel):
    pass


class MIPS64ELSysVGetsockname(Getsockname, MIPS64ELSysVModel):
    pass


class MIPS64ELSysVGetsockopt(Getsockopt, MIPS64ELSysVModel):
    pass


class MIPS64ELSysVListen(Listen, MIPS64ELSysVModel):
    pass


class MIPS64ELSysVRecv(Recv, MIPS64ELSysVModel):
    pass


class MIPS64ELSysVRecvfrom(Recvfrom, MIPS64ELSysVModel):
    pass


class MIPS64ELSysVRecvmsg(Recvmsg, MIPS64ELSysVModel):
    pass


class MIPS64ELSysVSend(Send, MIPS64ELSysVModel):
    pass


class MIPS64ELSysVSendmsg(Sendmsg, MIPS64ELSysVModel):
    pass


class MIPS64ELSysVSendto(Sendto, MIPS64ELSysVModel):
    pass


class MIPS64ELSysVSetsockopt(Setsockopt, MIPS64ELSysVModel):
    pass


class MIPS64ELSysVShutdown(Shutdown, MIPS64ELSysVModel):
    pass


class MIPS64ELSysVSocket(Socket, MIPS64ELSysVModel):
    pass


class MIPS64ELSysVSocketpair(Socketpair, MIPS64ELSysVModel):
    pass


__all__ = [
    "MIPS64ELSysVAccept",
    "MIPS64ELSysVBind",
    "MIPS64ELSysVConnect",
    "MIPS64ELSysVGetpeername",
    "MIPS64ELSysVGetsockname",
    "MIPS64ELSysVGetsockopt",
    "MIPS64ELSysVListen",
    "MIPS64ELSysVRecv",
    "MIPS64ELSysVRecvfrom",
    "MIPS64ELSysVRecvmsg",
    "MIPS64ELSysVSend",
    "MIPS64ELSysVSendmsg",
    "MIPS64ELSysVSendto",
    "MIPS64ELSysVSetsockopt",
    "MIPS64ELSysVShutdown",
    "MIPS64ELSysVSocket",
    "MIPS64ELSysVSocketpair",
]
