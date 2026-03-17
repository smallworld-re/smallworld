import typing

from .....platforms import Byteorder
from ...filedesc import FDIOInvalid, FDIOUnsupported, FileDescriptorManager
from .sockaddr import Sockaddr
from .socket import SocketIO

AF_UNIX = 1
AF_INET = 2
AF_INET6 = 10

SOCK_STREAM = 1
SOCK_DGRAM = 2

PROTO_DEFAULT = 0
PROTO_TCP = 6
PROTO_UDP = 17

SOCKET_CONFIGS = (
    (AF_UNIX, SOCK_STREAM, PROTO_DEFAULT),  # Unix stream
    (AF_UNIX, SOCK_DGRAM, PROTO_DEFAULT),  # Unix datagram
    (AF_INET, SOCK_STREAM, PROTO_DEFAULT),  # tcp/ip (default encoding)
    (AF_INET, SOCK_STREAM, PROTO_TCP),  # tcp/ip
    (AF_INET, SOCK_DGRAM, PROTO_DEFAULT),  # udp/ip (default encoding)
    (AF_INET, SOCK_DGRAM, PROTO_UDP),  # udp/ip
    (AF_INET6, SOCK_STREAM, PROTO_DEFAULT),  # tcp/ip6 (default encoding)
    (AF_INET6, SOCK_STREAM, PROTO_TCP),  # tcp/ip6
    (AF_INET6, SOCK_DGRAM, PROTO_DEFAULT),  # udp/ip6 (default encoding)
    (AF_INET6, SOCK_DGRAM, PROTO_UDP),  # udp/ip6
)


class POSIXFileDescriptorManager(FileDescriptorManager):
    def __init__(self):
        super().__init__()

        self._inbound: typing.Dict[Sockaddr, typing.List[SocketIO]]

    def accept(self, fd: int) -> typing.Tuple[int, SocketIO]:
        socket = self.get_fd(fd)

        if not isinstance(socket, SocketIO):
            raise FDIOInvalid(f"{fd} is not a socket")

        raise NotImplementedError("Accept not implemented")

    def bind(self, fd: int, addr_bytes: bytes) -> None:
        socket = self.get_fd(fd)

        if not isinstance(socket, SocketIO):
            raise FDIOInvalid(f"{fd} is not a socket")

        byteorder: typing.Literal["big", "little"]
        if self.platform.byteorder == Byteorder.BIG:
            byteorder = "big"
        else:
            byteorder = "little"

        sockname = Sockaddr.for_family(socket.domain)
        sockname.from_bytes(addr_bytes, byteorder)

    def connect(self, fd: int, addr_bytes: bytes) -> None:
        socket = self.get_fd(fd)

        if not isinstance(socket, SocketIO):
            raise FDIOInvalid(f"{fd} is not a socket")

        byteorder: typing.Literal["big", "little"]
        if self.platform.byteorder == Byteorder.BIG:
            byteorder = "big"
        else:
            byteorder = "little"

        peername = Sockaddr.for_family(socket.domain)
        peername.from_bytes(addr_bytes, byteorder)

    def socket(self, domain: int, type: int, protocol: int) -> int:
        fd = self._get_free_fd()

        if (domain, type, protocol) not in SOCKET_CONFIGS:
            raise FDIOUnsupported(
                f"Unknown domain/type/protocol: {domain}, {type}, {protocol}"
            )

        interactive = type == SOCK_DGRAM

        socket = SocketIO("Socket", domain, type, protocol, interactive)
        self._fds[fd] = socket

        return fd


__all__ = ["POSIXFileDescriptorManager"]
