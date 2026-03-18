from .....posix.sys.socket import (
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
from ...systemv import AArch64SysVModel


class AArch64SysVAccept(Accept, AArch64SysVModel):
    pass


class AArch64SysVBind(Bind, AArch64SysVModel):
    pass


class AArch64SysVConnect(Connect, AArch64SysVModel):
    pass


class AArch64SysVGetpeername(Getpeername, AArch64SysVModel):
    pass


class AArch64SysVGetsockname(Getsockname, AArch64SysVModel):
    pass


class AArch64SysVGetsockopt(Getsockopt, AArch64SysVModel):
    pass


class AArch64SysVListen(Listen, AArch64SysVModel):
    pass


class AArch64SysVRecv(Recv, AArch64SysVModel):
    pass


class AArch64SysVRecvfrom(Recvfrom, AArch64SysVModel):
    pass


class AArch64SysVRecvmsg(Recvmsg, AArch64SysVModel):
    pass


class AArch64SysVSend(Send, AArch64SysVModel):
    pass


class AArch64SysVSendmsg(Sendmsg, AArch64SysVModel):
    pass


class AArch64SysVSendto(Sendto, AArch64SysVModel):
    pass


class AArch64SysVSetsockopt(Setsockopt, AArch64SysVModel):
    pass


class AArch64SysVShutdown(Shutdown, AArch64SysVModel):
    pass


class AArch64SysVSocket(Socket, AArch64SysVModel):
    pass


class AArch64SysVSocketpair(Socketpair, AArch64SysVModel):
    pass


__all__ = [
    "AArch64SysVAccept",
    "AArch64SysVBind",
    "AArch64SysVConnect",
    "AArch64SysVGetpeername",
    "AArch64SysVGetsockname",
    "AArch64SysVGetsockopt",
    "AArch64SysVListen",
    "AArch64SysVRecv",
    "AArch64SysVRecvfrom",
    "AArch64SysVRecvmsg",
    "AArch64SysVSend",
    "AArch64SysVSendmsg",
    "AArch64SysVSendto",
    "AArch64SysVSetsockopt",
    "AArch64SysVShutdown",
    "AArch64SysVSocket",
    "AArch64SysVSocketpair",
]
