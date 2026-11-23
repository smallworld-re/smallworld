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
from ...systemv import ArmV8ABESysVModel


class ArmV8ABESysVAccept(Accept, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVBind(Bind, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVConnect(Connect, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVGetpeername(Getpeername, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVGetsockname(Getsockname, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVGetsockopt(Getsockopt, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVListen(Listen, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVRecv(Recv, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVRecvfrom(Recvfrom, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVRecvmsg(Recvmsg, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVSend(Send, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVSendmsg(Sendmsg, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVSendto(Sendto, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVSetsockopt(Setsockopt, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVShutdown(Shutdown, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVSocket(Socket, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVSocketpair(Socketpair, ArmV8ABESysVModel):
    pass


__all__ = [
    "ArmV8ABESysVAccept",
    "ArmV8ABESysVBind",
    "ArmV8ABESysVConnect",
    "ArmV8ABESysVGetpeername",
    "ArmV8ABESysVGetsockname",
    "ArmV8ABESysVGetsockopt",
    "ArmV8ABESysVListen",
    "ArmV8ABESysVRecv",
    "ArmV8ABESysVRecvfrom",
    "ArmV8ABESysVRecvmsg",
    "ArmV8ABESysVSend",
    "ArmV8ABESysVSendmsg",
    "ArmV8ABESysVSendto",
    "ArmV8ABESysVSetsockopt",
    "ArmV8ABESysVShutdown",
    "ArmV8ABESysVSocket",
    "ArmV8ABESysVSocketpair",
]
