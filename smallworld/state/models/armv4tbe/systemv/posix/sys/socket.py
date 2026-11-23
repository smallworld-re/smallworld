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
from ...systemv import ArmV4TBESysVModel


class ArmV4TBESysVAccept(Accept, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVBind(Bind, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVConnect(Connect, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVGetpeername(Getpeername, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVGetsockname(Getsockname, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVGetsockopt(Getsockopt, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVListen(Listen, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVRecv(Recv, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVRecvfrom(Recvfrom, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVRecvmsg(Recvmsg, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVSend(Send, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVSendmsg(Sendmsg, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVSendto(Sendto, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVSetsockopt(Setsockopt, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVShutdown(Shutdown, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVSocket(Socket, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVSocketpair(Socketpair, ArmV4TBESysVModel):
    pass


__all__ = [
    "ArmV4TBESysVAccept",
    "ArmV4TBESysVBind",
    "ArmV4TBESysVConnect",
    "ArmV4TBESysVGetpeername",
    "ArmV4TBESysVGetsockname",
    "ArmV4TBESysVGetsockopt",
    "ArmV4TBESysVListen",
    "ArmV4TBESysVRecv",
    "ArmV4TBESysVRecvfrom",
    "ArmV4TBESysVRecvmsg",
    "ArmV4TBESysVSend",
    "ArmV4TBESysVSendmsg",
    "ArmV4TBESysVSendto",
    "ArmV4TBESysVSetsockopt",
    "ArmV4TBESysVShutdown",
    "ArmV4TBESysVSocket",
    "ArmV4TBESysVSocketpair",
]
