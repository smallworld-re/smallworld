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
from ...systemv import ArmV7ASysVModel


class ArmV7ASysVAccept(Accept, ArmV7ASysVModel):
    pass


class ArmV7ASysVBind(Bind, ArmV7ASysVModel):
    pass


class ArmV7ASysVConnect(Connect, ArmV7ASysVModel):
    pass


class ArmV7ASysVGetpeername(Getpeername, ArmV7ASysVModel):
    pass


class ArmV7ASysVGetsockname(Getsockname, ArmV7ASysVModel):
    pass


class ArmV7ASysVGetsockopt(Getsockopt, ArmV7ASysVModel):
    pass


class ArmV7ASysVListen(Listen, ArmV7ASysVModel):
    pass


class ArmV7ASysVRecv(Recv, ArmV7ASysVModel):
    pass


class ArmV7ASysVRecvfrom(Recvfrom, ArmV7ASysVModel):
    pass


class ArmV7ASysVRecvmsg(Recvmsg, ArmV7ASysVModel):
    pass


class ArmV7ASysVSend(Send, ArmV7ASysVModel):
    pass


class ArmV7ASysVSendmsg(Sendmsg, ArmV7ASysVModel):
    pass


class ArmV7ASysVSendto(Sendto, ArmV7ASysVModel):
    pass


class ArmV7ASysVSetsockopt(Setsockopt, ArmV7ASysVModel):
    pass


class ArmV7ASysVShutdown(Shutdown, ArmV7ASysVModel):
    pass


class ArmV7ASysVSocket(Socket, ArmV7ASysVModel):
    pass


class ArmV7ASysVSocketpair(Socketpair, ArmV7ASysVModel):
    pass


__all__ = [
    "ArmV7ASysVAccept",
    "ArmV7ASysVBind",
    "ArmV7ASysVConnect",
    "ArmV7ASysVGetpeername",
    "ArmV7ASysVGetsockname",
    "ArmV7ASysVGetsockopt",
    "ArmV7ASysVListen",
    "ArmV7ASysVRecv",
    "ArmV7ASysVRecvfrom",
    "ArmV7ASysVRecvmsg",
    "ArmV7ASysVSend",
    "ArmV7ASysVSendmsg",
    "ArmV7ASysVSendto",
    "ArmV7ASysVSetsockopt",
    "ArmV7ASysVShutdown",
    "ArmV7ASysVSocket",
    "ArmV7ASysVSocketpair",
]
