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
from ...systemv import ArmV8RSysVModel


class ArmV8RSysVAccept(Accept, ArmV8RSysVModel):
    pass


class ArmV8RSysVBind(Bind, ArmV8RSysVModel):
    pass


class ArmV8RSysVConnect(Connect, ArmV8RSysVModel):
    pass


class ArmV8RSysVGetpeername(Getpeername, ArmV8RSysVModel):
    pass


class ArmV8RSysVGetsockname(Getsockname, ArmV8RSysVModel):
    pass


class ArmV8RSysVGetsockopt(Getsockopt, ArmV8RSysVModel):
    pass


class ArmV8RSysVListen(Listen, ArmV8RSysVModel):
    pass


class ArmV8RSysVRecv(Recv, ArmV8RSysVModel):
    pass


class ArmV8RSysVRecvfrom(Recvfrom, ArmV8RSysVModel):
    pass


class ArmV8RSysVRecvmsg(Recvmsg, ArmV8RSysVModel):
    pass


class ArmV8RSysVSend(Send, ArmV8RSysVModel):
    pass


class ArmV8RSysVSendmsg(Sendmsg, ArmV8RSysVModel):
    pass


class ArmV8RSysVSendto(Sendto, ArmV8RSysVModel):
    pass


class ArmV8RSysVSetsockopt(Setsockopt, ArmV8RSysVModel):
    pass


class ArmV8RSysVShutdown(Shutdown, ArmV8RSysVModel):
    pass


class ArmV8RSysVSocket(Socket, ArmV8RSysVModel):
    pass


class ArmV8RSysVSocketpair(Socketpair, ArmV8RSysVModel):
    pass


__all__ = [
    "ArmV8RSysVAccept",
    "ArmV8RSysVBind",
    "ArmV8RSysVConnect",
    "ArmV8RSysVGetpeername",
    "ArmV8RSysVGetsockname",
    "ArmV8RSysVGetsockopt",
    "ArmV8RSysVListen",
    "ArmV8RSysVRecv",
    "ArmV8RSysVRecvfrom",
    "ArmV8RSysVRecvmsg",
    "ArmV8RSysVSend",
    "ArmV8RSysVSendmsg",
    "ArmV8RSysVSendto",
    "ArmV8RSysVSetsockopt",
    "ArmV8RSysVShutdown",
    "ArmV8RSysVSocket",
    "ArmV8RSysVSocketpair",
]
