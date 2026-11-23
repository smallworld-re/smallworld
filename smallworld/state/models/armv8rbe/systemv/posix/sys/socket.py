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
from ...systemv import ArmV8RBESysVModel


class ArmV8RBESysVAccept(Accept, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVBind(Bind, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVConnect(Connect, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVGetpeername(Getpeername, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVGetsockname(Getsockname, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVGetsockopt(Getsockopt, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVListen(Listen, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVRecv(Recv, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVRecvfrom(Recvfrom, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVRecvmsg(Recvmsg, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVSend(Send, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVSendmsg(Sendmsg, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVSendto(Sendto, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVSetsockopt(Setsockopt, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVShutdown(Shutdown, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVSocket(Socket, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVSocketpair(Socketpair, ArmV8RBESysVModel):
    pass


__all__ = [
    "ArmV8RBESysVAccept",
    "ArmV8RBESysVBind",
    "ArmV8RBESysVConnect",
    "ArmV8RBESysVGetpeername",
    "ArmV8RBESysVGetsockname",
    "ArmV8RBESysVGetsockopt",
    "ArmV8RBESysVListen",
    "ArmV8RBESysVRecv",
    "ArmV8RBESysVRecvfrom",
    "ArmV8RBESysVRecvmsg",
    "ArmV8RBESysVSend",
    "ArmV8RBESysVSendmsg",
    "ArmV8RBESysVSendto",
    "ArmV8RBESysVSetsockopt",
    "ArmV8RBESysVShutdown",
    "ArmV8RBESysVSocket",
    "ArmV8RBESysVSocketpair",
]
