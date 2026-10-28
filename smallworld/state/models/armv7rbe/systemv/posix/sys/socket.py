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
from ...systemv import ArmV7RBESysVModel


class ArmV7RBESysVAccept(Accept, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVBind(Bind, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVConnect(Connect, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVGetpeername(Getpeername, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVGetsockname(Getsockname, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVGetsockopt(Getsockopt, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVListen(Listen, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVRecv(Recv, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVRecvfrom(Recvfrom, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVRecvmsg(Recvmsg, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVSend(Send, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVSendmsg(Sendmsg, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVSendto(Sendto, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVSetsockopt(Setsockopt, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVShutdown(Shutdown, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVSocket(Socket, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVSocketpair(Socketpair, ArmV7RBESysVModel):
    pass


__all__ = [
    "ArmV7RBESysVAccept",
    "ArmV7RBESysVBind",
    "ArmV7RBESysVConnect",
    "ArmV7RBESysVGetpeername",
    "ArmV7RBESysVGetsockname",
    "ArmV7RBESysVGetsockopt",
    "ArmV7RBESysVListen",
    "ArmV7RBESysVRecv",
    "ArmV7RBESysVRecvfrom",
    "ArmV7RBESysVRecvmsg",
    "ArmV7RBESysVSend",
    "ArmV7RBESysVSendmsg",
    "ArmV7RBESysVSendto",
    "ArmV7RBESysVSetsockopt",
    "ArmV7RBESysVShutdown",
    "ArmV7RBESysVSocket",
    "ArmV7RBESysVSocketpair",
]
