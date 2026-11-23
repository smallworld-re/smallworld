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
from ...systemv import RiscV32SysVModel


class RiscV32SysVAccept(Accept, RiscV32SysVModel):
    pass


class RiscV32SysVBind(Bind, RiscV32SysVModel):
    pass


class RiscV32SysVConnect(Connect, RiscV32SysVModel):
    pass


class RiscV32SysVGetpeername(Getpeername, RiscV32SysVModel):
    pass


class RiscV32SysVGetsockname(Getsockname, RiscV32SysVModel):
    pass


class RiscV32SysVGetsockopt(Getsockopt, RiscV32SysVModel):
    pass


class RiscV32SysVListen(Listen, RiscV32SysVModel):
    pass


class RiscV32SysVRecv(Recv, RiscV32SysVModel):
    pass


class RiscV32SysVRecvfrom(Recvfrom, RiscV32SysVModel):
    pass


class RiscV32SysVRecvmsg(Recvmsg, RiscV32SysVModel):
    pass


class RiscV32SysVSend(Send, RiscV32SysVModel):
    pass


class RiscV32SysVSendmsg(Sendmsg, RiscV32SysVModel):
    pass


class RiscV32SysVSendto(Sendto, RiscV32SysVModel):
    pass


class RiscV32SysVSetsockopt(Setsockopt, RiscV32SysVModel):
    pass


class RiscV32SysVShutdown(Shutdown, RiscV32SysVModel):
    pass


class RiscV32SysVSocket(Socket, RiscV32SysVModel):
    pass


class RiscV32SysVSocketpair(Socketpair, RiscV32SysVModel):
    pass


__all__ = [
    "RiscV32SysVAccept",
    "RiscV32SysVBind",
    "RiscV32SysVConnect",
    "RiscV32SysVGetpeername",
    "RiscV32SysVGetsockname",
    "RiscV32SysVGetsockopt",
    "RiscV32SysVListen",
    "RiscV32SysVRecv",
    "RiscV32SysVRecvfrom",
    "RiscV32SysVRecvmsg",
    "RiscV32SysVSend",
    "RiscV32SysVSendmsg",
    "RiscV32SysVSendto",
    "RiscV32SysVSetsockopt",
    "RiscV32SysVShutdown",
    "RiscV32SysVSocket",
    "RiscV32SysVSocketpair",
]
