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
from ...systemv import ArmV5TSysVModel


class ArmV5TSysVAccept(Accept, ArmV5TSysVModel):
    pass


class ArmV5TSysVBind(Bind, ArmV5TSysVModel):
    pass


class ArmV5TSysVConnect(Connect, ArmV5TSysVModel):
    pass


class ArmV5TSysVGetpeername(Getpeername, ArmV5TSysVModel):
    pass


class ArmV5TSysVGetsockname(Getsockname, ArmV5TSysVModel):
    pass


class ArmV5TSysVGetsockopt(Getsockopt, ArmV5TSysVModel):
    pass


class ArmV5TSysVListen(Listen, ArmV5TSysVModel):
    pass


class ArmV5TSysVRecv(Recv, ArmV5TSysVModel):
    pass


class ArmV5TSysVRecvfrom(Recvfrom, ArmV5TSysVModel):
    pass


class ArmV5TSysVRecvmsg(Recvmsg, ArmV5TSysVModel):
    pass


class ArmV5TSysVSend(Send, ArmV5TSysVModel):
    pass


class ArmV5TSysVSendmsg(Sendmsg, ArmV5TSysVModel):
    pass


class ArmV5TSysVSendto(Sendto, ArmV5TSysVModel):
    pass


class ArmV5TSysVSetsockopt(Setsockopt, ArmV5TSysVModel):
    pass


class ArmV5TSysVShutdown(Shutdown, ArmV5TSysVModel):
    pass


class ArmV5TSysVSocket(Socket, ArmV5TSysVModel):
    pass


class ArmV5TSysVSocketpair(Socketpair, ArmV5TSysVModel):
    pass


__all__ = [
    "ArmV5TSysVAccept",
    "ArmV5TSysVBind",
    "ArmV5TSysVConnect",
    "ArmV5TSysVGetpeername",
    "ArmV5TSysVGetsockname",
    "ArmV5TSysVGetsockopt",
    "ArmV5TSysVListen",
    "ArmV5TSysVRecv",
    "ArmV5TSysVRecvfrom",
    "ArmV5TSysVRecvmsg",
    "ArmV5TSysVSend",
    "ArmV5TSysVSendmsg",
    "ArmV5TSysVSendto",
    "ArmV5TSysVSetsockopt",
    "ArmV5TSysVShutdown",
    "ArmV5TSysVSocket",
    "ArmV5TSysVSocketpair",
]
