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
from ...systemv import ArmELSysVModel


class ArmELSysVAccept(Accept, ArmELSysVModel):
    pass


class ArmELSysVBind(Bind, ArmELSysVModel):
    pass


class ArmELSysVConnect(Connect, ArmELSysVModel):
    pass


class ArmELSysVGetpeername(Getpeername, ArmELSysVModel):
    pass


class ArmELSysVGetsockname(Getsockname, ArmELSysVModel):
    pass


class ArmELSysVGetsockopt(Getsockopt, ArmELSysVModel):
    pass


class ArmELSysVListen(Listen, ArmELSysVModel):
    pass


class ArmELSysVRecv(Recv, ArmELSysVModel):
    pass


class ArmELSysVRecvfrom(Recvfrom, ArmELSysVModel):
    pass


class ArmELSysVRecvmsg(Recvmsg, ArmELSysVModel):
    pass


class ArmELSysVSend(Send, ArmELSysVModel):
    pass


class ArmELSysVSendmsg(Sendmsg, ArmELSysVModel):
    pass


class ArmELSysVSendto(Sendto, ArmELSysVModel):
    pass


class ArmELSysVSetsockopt(Setsockopt, ArmELSysVModel):
    pass


class ArmELSysVShutdown(Shutdown, ArmELSysVModel):
    pass


class ArmELSysVSocket(Socket, ArmELSysVModel):
    pass


class ArmELSysVSocketpair(Socketpair, ArmELSysVModel):
    pass


__all__ = [
    "ArmELSysVAccept",
    "ArmELSysVBind",
    "ArmELSysVConnect",
    "ArmELSysVGetpeername",
    "ArmELSysVGetsockname",
    "ArmELSysVGetsockopt",
    "ArmELSysVListen",
    "ArmELSysVRecv",
    "ArmELSysVRecvfrom",
    "ArmELSysVRecvmsg",
    "ArmELSysVSend",
    "ArmELSysVSendmsg",
    "ArmELSysVSendto",
    "ArmELSysVSetsockopt",
    "ArmELSysVShutdown",
    "ArmELSysVSocket",
    "ArmELSysVSocketpair",
]
