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
from ...systemv import MIPS64SysVModel


class MIPS64SysVAccept(Accept, MIPS64SysVModel):
    pass


class MIPS64SysVBind(Bind, MIPS64SysVModel):
    pass


class MIPS64SysVConnect(Connect, MIPS64SysVModel):
    pass


class MIPS64SysVGetpeername(Getpeername, MIPS64SysVModel):
    pass


class MIPS64SysVGetsockname(Getsockname, MIPS64SysVModel):
    pass


class MIPS64SysVGetsockopt(Getsockopt, MIPS64SysVModel):
    pass


class MIPS64SysVListen(Listen, MIPS64SysVModel):
    pass


class MIPS64SysVRecv(Recv, MIPS64SysVModel):
    pass


class MIPS64SysVRecvfrom(Recvfrom, MIPS64SysVModel):
    pass


class MIPS64SysVRecvmsg(Recvmsg, MIPS64SysVModel):
    pass


class MIPS64SysVSend(Send, MIPS64SysVModel):
    pass


class MIPS64SysVSendmsg(Sendmsg, MIPS64SysVModel):
    pass


class MIPS64SysVSendto(Sendto, MIPS64SysVModel):
    pass


class MIPS64SysVSetsockopt(Setsockopt, MIPS64SysVModel):
    pass


class MIPS64SysVShutdown(Shutdown, MIPS64SysVModel):
    pass


class MIPS64SysVSocket(Socket, MIPS64SysVModel):
    pass


class MIPS64SysVSocketpair(Socketpair, MIPS64SysVModel):
    pass


__all__ = [
    "MIPS64SysVAccept",
    "MIPS64SysVBind",
    "MIPS64SysVConnect",
    "MIPS64SysVGetpeername",
    "MIPS64SysVGetsockname",
    "MIPS64SysVGetsockopt",
    "MIPS64SysVListen",
    "MIPS64SysVRecv",
    "MIPS64SysVRecvfrom",
    "MIPS64SysVRecvmsg",
    "MIPS64SysVSend",
    "MIPS64SysVSendmsg",
    "MIPS64SysVSendto",
    "MIPS64SysVSetsockopt",
    "MIPS64SysVShutdown",
    "MIPS64SysVSocket",
    "MIPS64SysVSocketpair",
]
