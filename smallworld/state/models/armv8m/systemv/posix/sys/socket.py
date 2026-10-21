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
from ...systemv import ArmV8MSysVModel


class ArmV8MSysVAccept(Accept, ArmV8MSysVModel):
    pass


class ArmV8MSysVBind(Bind, ArmV8MSysVModel):
    pass


class ArmV8MSysVConnect(Connect, ArmV8MSysVModel):
    pass


class ArmV8MSysVGetpeername(Getpeername, ArmV8MSysVModel):
    pass


class ArmV8MSysVGetsockname(Getsockname, ArmV8MSysVModel):
    pass


class ArmV8MSysVGetsockopt(Getsockopt, ArmV8MSysVModel):
    pass


class ArmV8MSysVListen(Listen, ArmV8MSysVModel):
    pass


class ArmV8MSysVRecv(Recv, ArmV8MSysVModel):
    pass


class ArmV8MSysVRecvfrom(Recvfrom, ArmV8MSysVModel):
    pass


class ArmV8MSysVRecvmsg(Recvmsg, ArmV8MSysVModel):
    pass


class ArmV8MSysVSend(Send, ArmV8MSysVModel):
    pass


class ArmV8MSysVSendmsg(Sendmsg, ArmV8MSysVModel):
    pass


class ArmV8MSysVSendto(Sendto, ArmV8MSysVModel):
    pass


class ArmV8MSysVSetsockopt(Setsockopt, ArmV8MSysVModel):
    pass


class ArmV8MSysVShutdown(Shutdown, ArmV8MSysVModel):
    pass


class ArmV8MSysVSocket(Socket, ArmV8MSysVModel):
    pass


class ArmV8MSysVSocketpair(Socketpair, ArmV8MSysVModel):
    pass


__all__ = [
    "ArmV8MSysVAccept",
    "ArmV8MSysVBind",
    "ArmV8MSysVConnect",
    "ArmV8MSysVGetpeername",
    "ArmV8MSysVGetsockname",
    "ArmV8MSysVGetsockopt",
    "ArmV8MSysVListen",
    "ArmV8MSysVRecv",
    "ArmV8MSysVRecvfrom",
    "ArmV8MSysVRecvmsg",
    "ArmV8MSysVSend",
    "ArmV8MSysVSendmsg",
    "ArmV8MSysVSendto",
    "ArmV8MSysVSetsockopt",
    "ArmV8MSysVShutdown",
    "ArmV8MSysVSocket",
    "ArmV8MSysVSocketpair",
]
