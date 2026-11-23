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
from ...systemv import ArmV7ABESysVModel


class ArmV7ABESysVAccept(Accept, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVBind(Bind, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVConnect(Connect, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVGetpeername(Getpeername, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVGetsockname(Getsockname, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVGetsockopt(Getsockopt, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVListen(Listen, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVRecv(Recv, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVRecvfrom(Recvfrom, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVRecvmsg(Recvmsg, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVSend(Send, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVSendmsg(Sendmsg, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVSendto(Sendto, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVSetsockopt(Setsockopt, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVShutdown(Shutdown, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVSocket(Socket, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVSocketpair(Socketpair, ArmV7ABESysVModel):
    pass


__all__ = [
    "ArmV7ABESysVAccept",
    "ArmV7ABESysVBind",
    "ArmV7ABESysVConnect",
    "ArmV7ABESysVGetpeername",
    "ArmV7ABESysVGetsockname",
    "ArmV7ABESysVGetsockopt",
    "ArmV7ABESysVListen",
    "ArmV7ABESysVRecv",
    "ArmV7ABESysVRecvfrom",
    "ArmV7ABESysVRecvmsg",
    "ArmV7ABESysVSend",
    "ArmV7ABESysVSendmsg",
    "ArmV7ABESysVSendto",
    "ArmV7ABESysVSetsockopt",
    "ArmV7ABESysVShutdown",
    "ArmV7ABESysVSocket",
    "ArmV7ABESysVSocketpair",
]
