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
from ...systemv import PowerPC64SysVModel


class PowerPC64SysVAccept(Accept, PowerPC64SysVModel):
    pass


class PowerPC64SysVBind(Bind, PowerPC64SysVModel):
    pass


class PowerPC64SysVConnect(Connect, PowerPC64SysVModel):
    pass


class PowerPC64SysVGetpeername(Getpeername, PowerPC64SysVModel):
    pass


class PowerPC64SysVGetsockname(Getsockname, PowerPC64SysVModel):
    pass


class PowerPC64SysVGetsockopt(Getsockopt, PowerPC64SysVModel):
    pass


class PowerPC64SysVListen(Listen, PowerPC64SysVModel):
    pass


class PowerPC64SysVRecv(Recv, PowerPC64SysVModel):
    pass


class PowerPC64SysVRecvfrom(Recvfrom, PowerPC64SysVModel):
    pass


class PowerPC64SysVRecvmsg(Recvmsg, PowerPC64SysVModel):
    pass


class PowerPC64SysVSend(Send, PowerPC64SysVModel):
    pass


class PowerPC64SysVSendmsg(Sendmsg, PowerPC64SysVModel):
    pass


class PowerPC64SysVSendto(Sendto, PowerPC64SysVModel):
    pass


class PowerPC64SysVSetsockopt(Setsockopt, PowerPC64SysVModel):
    pass


class PowerPC64SysVShutdown(Shutdown, PowerPC64SysVModel):
    pass


class PowerPC64SysVSocket(Socket, PowerPC64SysVModel):
    pass


class PowerPC64SysVSocketpair(Socketpair, PowerPC64SysVModel):
    pass


__all__ = [
    "PowerPC64SysVAccept",
    "PowerPC64SysVBind",
    "PowerPC64SysVConnect",
    "PowerPC64SysVGetpeername",
    "PowerPC64SysVGetsockname",
    "PowerPC64SysVGetsockopt",
    "PowerPC64SysVListen",
    "PowerPC64SysVRecv",
    "PowerPC64SysVRecvfrom",
    "PowerPC64SysVRecvmsg",
    "PowerPC64SysVSend",
    "PowerPC64SysVSendmsg",
    "PowerPC64SysVSendto",
    "PowerPC64SysVSetsockopt",
    "PowerPC64SysVShutdown",
    "PowerPC64SysVSocket",
    "PowerPC64SysVSocketpair",
]
