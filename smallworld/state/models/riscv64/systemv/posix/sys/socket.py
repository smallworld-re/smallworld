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
from ...systemv import RiscV64SysVModel


class RiscV64SysVAccept(Accept, RiscV64SysVModel):
    pass


class RiscV64SysVBind(Bind, RiscV64SysVModel):
    pass


class RiscV64SysVConnect(Connect, RiscV64SysVModel):
    pass


class RiscV64SysVGetpeername(Getpeername, RiscV64SysVModel):
    pass


class RiscV64SysVGetsockname(Getsockname, RiscV64SysVModel):
    pass


class RiscV64SysVGetsockopt(Getsockopt, RiscV64SysVModel):
    pass


class RiscV64SysVListen(Listen, RiscV64SysVModel):
    pass


class RiscV64SysVRecv(Recv, RiscV64SysVModel):
    pass


class RiscV64SysVRecvfrom(Recvfrom, RiscV64SysVModel):
    pass


class RiscV64SysVRecvmsg(Recvmsg, RiscV64SysVModel):
    pass


class RiscV64SysVSend(Send, RiscV64SysVModel):
    pass


class RiscV64SysVSendmsg(Sendmsg, RiscV64SysVModel):
    pass


class RiscV64SysVSendto(Sendto, RiscV64SysVModel):
    pass


class RiscV64SysVSetsockopt(Setsockopt, RiscV64SysVModel):
    pass


class RiscV64SysVShutdown(Shutdown, RiscV64SysVModel):
    pass


class RiscV64SysVSocket(Socket, RiscV64SysVModel):
    pass


class RiscV64SysVSocketpair(Socketpair, RiscV64SysVModel):
    pass


__all__ = [
    "RiscV64SysVAccept",
    "RiscV64SysVBind",
    "RiscV64SysVConnect",
    "RiscV64SysVGetpeername",
    "RiscV64SysVGetsockname",
    "RiscV64SysVGetsockopt",
    "RiscV64SysVListen",
    "RiscV64SysVRecv",
    "RiscV64SysVRecvfrom",
    "RiscV64SysVRecvmsg",
    "RiscV64SysVSend",
    "RiscV64SysVSendmsg",
    "RiscV64SysVSendto",
    "RiscV64SysVSetsockopt",
    "RiscV64SysVShutdown",
    "RiscV64SysVSocket",
    "RiscV64SysVSocketpair",
]
