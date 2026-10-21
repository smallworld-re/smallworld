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
from ...systemv import ArmV8ASysVModel


class ArmV8ASysVAccept(Accept, ArmV8ASysVModel):
    pass


class ArmV8ASysVBind(Bind, ArmV8ASysVModel):
    pass


class ArmV8ASysVConnect(Connect, ArmV8ASysVModel):
    pass


class ArmV8ASysVGetpeername(Getpeername, ArmV8ASysVModel):
    pass


class ArmV8ASysVGetsockname(Getsockname, ArmV8ASysVModel):
    pass


class ArmV8ASysVGetsockopt(Getsockopt, ArmV8ASysVModel):
    pass


class ArmV8ASysVListen(Listen, ArmV8ASysVModel):
    pass


class ArmV8ASysVRecv(Recv, ArmV8ASysVModel):
    pass


class ArmV8ASysVRecvfrom(Recvfrom, ArmV8ASysVModel):
    pass


class ArmV8ASysVRecvmsg(Recvmsg, ArmV8ASysVModel):
    pass


class ArmV8ASysVSend(Send, ArmV8ASysVModel):
    pass


class ArmV8ASysVSendmsg(Sendmsg, ArmV8ASysVModel):
    pass


class ArmV8ASysVSendto(Sendto, ArmV8ASysVModel):
    pass


class ArmV8ASysVSetsockopt(Setsockopt, ArmV8ASysVModel):
    pass


class ArmV8ASysVShutdown(Shutdown, ArmV8ASysVModel):
    pass


class ArmV8ASysVSocket(Socket, ArmV8ASysVModel):
    pass


class ArmV8ASysVSocketpair(Socketpair, ArmV8ASysVModel):
    pass


__all__ = [
    "ArmV8ASysVAccept",
    "ArmV8ASysVBind",
    "ArmV8ASysVConnect",
    "ArmV8ASysVGetpeername",
    "ArmV8ASysVGetsockname",
    "ArmV8ASysVGetsockopt",
    "ArmV8ASysVListen",
    "ArmV8ASysVRecv",
    "ArmV8ASysVRecvfrom",
    "ArmV8ASysVRecvmsg",
    "ArmV8ASysVSend",
    "ArmV8ASysVSendmsg",
    "ArmV8ASysVSendto",
    "ArmV8ASysVSetsockopt",
    "ArmV8ASysVShutdown",
    "ArmV8ASysVSocket",
    "ArmV8ASysVSocketpair",
]
