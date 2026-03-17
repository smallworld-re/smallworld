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
from ...systemv import LoongArch64SysVModel


class LoongArch64SysVAccept(Accept, LoongArch64SysVModel):
    pass


class LoongArch64SysVBind(Bind, LoongArch64SysVModel):
    pass


class LoongArch64SysVConnect(Connect, LoongArch64SysVModel):
    pass


class LoongArch64SysVGetpeername(Getpeername, LoongArch64SysVModel):
    pass


class LoongArch64SysVGetsockname(Getsockname, LoongArch64SysVModel):
    pass


class LoongArch64SysVGetsockopt(Getsockopt, LoongArch64SysVModel):
    pass


class LoongArch64SysVListen(Listen, LoongArch64SysVModel):
    pass


class LoongArch64SysVRecv(Recv, LoongArch64SysVModel):
    pass


class LoongArch64SysVRecvfrom(Recvfrom, LoongArch64SysVModel):
    pass


class LoongArch64SysVRecvmsg(Recvmsg, LoongArch64SysVModel):
    pass


class LoongArch64SysVSend(Send, LoongArch64SysVModel):
    pass


class LoongArch64SysVSendmsg(Sendmsg, LoongArch64SysVModel):
    pass


class LoongArch64SysVSendto(Sendto, LoongArch64SysVModel):
    pass


class LoongArch64SysVSetsockopt(Setsockopt, LoongArch64SysVModel):
    pass


class LoongArch64SysVShutdown(Shutdown, LoongArch64SysVModel):
    pass


class LoongArch64SysVSocket(Socket, LoongArch64SysVModel):
    pass


class LoongArch64SysVSocketpair(Socketpair, LoongArch64SysVModel):
    pass


__all__ = [
    "LoongArch64SysVAccept",
    "LoongArch64SysVBind",
    "LoongArch64SysVConnect",
    "LoongArch64SysVGetpeername",
    "LoongArch64SysVGetsockname",
    "LoongArch64SysVGetsockopt",
    "LoongArch64SysVListen",
    "LoongArch64SysVRecv",
    "LoongArch64SysVRecvfrom",
    "LoongArch64SysVRecvmsg",
    "LoongArch64SysVSend",
    "LoongArch64SysVSendmsg",
    "LoongArch64SysVSendto",
    "LoongArch64SysVSetsockopt",
    "LoongArch64SysVShutdown",
    "LoongArch64SysVSocket",
    "LoongArch64SysVSocketpair",
]
