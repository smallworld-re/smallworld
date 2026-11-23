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
from ...systemv import ArmV7RSysVModel


class ArmV7RSysVAccept(Accept, ArmV7RSysVModel):
    pass


class ArmV7RSysVBind(Bind, ArmV7RSysVModel):
    pass


class ArmV7RSysVConnect(Connect, ArmV7RSysVModel):
    pass


class ArmV7RSysVGetpeername(Getpeername, ArmV7RSysVModel):
    pass


class ArmV7RSysVGetsockname(Getsockname, ArmV7RSysVModel):
    pass


class ArmV7RSysVGetsockopt(Getsockopt, ArmV7RSysVModel):
    pass


class ArmV7RSysVListen(Listen, ArmV7RSysVModel):
    pass


class ArmV7RSysVRecv(Recv, ArmV7RSysVModel):
    pass


class ArmV7RSysVRecvfrom(Recvfrom, ArmV7RSysVModel):
    pass


class ArmV7RSysVRecvmsg(Recvmsg, ArmV7RSysVModel):
    pass


class ArmV7RSysVSend(Send, ArmV7RSysVModel):
    pass


class ArmV7RSysVSendmsg(Sendmsg, ArmV7RSysVModel):
    pass


class ArmV7RSysVSendto(Sendto, ArmV7RSysVModel):
    pass


class ArmV7RSysVSetsockopt(Setsockopt, ArmV7RSysVModel):
    pass


class ArmV7RSysVShutdown(Shutdown, ArmV7RSysVModel):
    pass


class ArmV7RSysVSocket(Socket, ArmV7RSysVModel):
    pass


class ArmV7RSysVSocketpair(Socketpair, ArmV7RSysVModel):
    pass


__all__ = [
    "ArmV7RSysVAccept",
    "ArmV7RSysVBind",
    "ArmV7RSysVConnect",
    "ArmV7RSysVGetpeername",
    "ArmV7RSysVGetsockname",
    "ArmV7RSysVGetsockopt",
    "ArmV7RSysVListen",
    "ArmV7RSysVRecv",
    "ArmV7RSysVRecvfrom",
    "ArmV7RSysVRecvmsg",
    "ArmV7RSysVSend",
    "ArmV7RSysVSendmsg",
    "ArmV7RSysVSendto",
    "ArmV7RSysVSetsockopt",
    "ArmV7RSysVShutdown",
    "ArmV7RSysVSocket",
    "ArmV7RSysVSocketpair",
]
