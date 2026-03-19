import abc
import typing

from .....utils import find_subclass


class Sockaddr(abc.ABC):
    @property
    @abc.abstractmethod
    def family(self) -> int:
        raise NotImplementedError("Abstract method")

    @property
    @abc.abstractmethod
    def size(self) -> int:
        raise NotImplementedError("Abstract method")

    @abc.abstractmethod
    def from_bytes(
        self, data: bytes, byteorder: typing.Literal["big", "little"]
    ) -> None:
        raise NotImplementedError("Abstract method")

    @abc.abstractmethod
    def to_bytes(self, byteorder: typing.Literal["big", "little"]) -> bytes:
        raise NotImplementedError("Abstract method")

    @abc.abstractmethod
    def __eq__(self, other: typing.Any) -> bool:
        raise NotImplementedError("Abstract method")

    @abc.abstractmethod
    def __hash__(self) -> int:
        raise NotImplementedError("Abstract method")

    @classmethod
    def for_family(cls, family: int) -> "Sockaddr":
        try:
            return find_subclass(cls, lambda x: x.family == family)
        except ValueError:
            raise ValueError(f"No sockaddr struct for family {family}")


class SockaddrUn(Sockaddr):
    family = 1
    size = 110

    def __init__(self, name: str = ""):
        self.name = name

    def from_bytes(
        self, data: bytes, byteorder: typing.Literal["big", "little"]
    ) -> None:
        if len(data) != self.size:
            raise ValueError(f"Unix socket address must be 110 bytes; got {len(data)}")

        family = int.from_bytes(data[0:2], byteorder)
        if family != self.family:
            raise ValueError(f"Expected unix socket, got family {family}")

        self.name = data[2:].decode("utf-8").split("\0", 1)[0]

    def to_bytes(self, byteorder: typing.Literal["big", "little"]) -> bytes:
        name = self.name.encode("utf-8") + b"\0"
        if len(name) > 108:
            raise ValueError(
                f"Unix socket name can be at most 108 bytes; got {len(name)}"
            )

        out = self.family.to_bytes(2, byteorder)
        out += name
        return out

    def __eq__(self, other):
        return isinstance(other, SockaddrUn) and self.name == other.name

    def __hash__(self):
        return hash(self.name)

    def __repr__(self):
        return f"AF_UNIX:{self.name}"


class SockaddrIn(Sockaddr):
    family = 2
    size = 16

    def __init__(self, addr: int = 0, port: int = 0):
        self.addr = addr
        self.port = port

    def from_bytes(
        self, data: bytes, byteorder: typing.Literal["big", "little"]
    ) -> None:
        if len(data) != self.size:
            raise ValueError(f"Unix socket address must be 110 bytes; got {len(data)}")

        family = int.from_bytes(data[0:2], byteorder)
        if family != self.family:
            raise ValueError(f"Expected unix socket, got family {family}")

        self.port = int.from_bytes(data[2:4], "big")
        self.addr = int.from_bytes(data[4:8], "big")

    def to_bytes(self, byteorder: typing.Literal["big", "little"]) -> bytes:
        out = self.family.to_bytes(2, byteorder)
        out += self.port.to_bytes(2, "big")
        out += self.addr.to_bytes(4, "big")
        out += b"\0" * 8

        return out

    def __eq__(self, other) -> bool:
        return (
            isinstance(other, SockaddrIn)
            and self.addr == other.addr
            and self.port == other.port
        )

    def __hash__(self) -> int:
        return hash((self.addr, self.port))

    def __repr__(self) -> str:
        a = (self.addr >> 24) & 0xFF
        b = (self.addr >> 16) & 0xFF
        c = (self.addr >> 8) & 0xFF
        d = (self.addr) & 0xFF
        return f"AF_INET:{a}.{b}.{c}.{d}:{self.port}"


class SockaddrIn6(Sockaddr):
    family = 10
    size = 28

    def __init__(
        self,
        addr: bytes = b"\0" * 16,
        port: int = 0,
        flowinfo: int = 0,
        scopeid: int = 0,
    ):
        if len(addr) != 16:
            raise ValueError(f"IPv6 addresses must be 16 bytes, got {len(addr)}")
        self.addr = addr
        self.port = port
        self.flowinfo = flowinfo
        self.scopeid = scopeid

    def from_bytes(
        self, data: bytes, byteorder: typing.Literal["big", "little"]
    ) -> None:
        if len(data) != self.size:
            raise ValueError(f"Unix socket address must be 110 bytes; got {len(data)}")

        family = int.from_bytes(data[0:2], byteorder)
        if family != self.family:
            raise ValueError(f"Expected unix socket, got family {family}")

        self.port = int.from_bytes(data[2:4], "big")
        self.flowinfo = int.from_bytes(data[4:8], "big")
        self.addr = data[8:24]
        self.scopeid = int.from_bytes(data[24:28], "big")

    def to_bytes(self, byteorder: typing.Literal["big", "little"]) -> bytes:
        out = self.family.to_bytes(2, byteorder)
        out += self.port.to_bytes(2, "big")
        out += self.flowinfo.to_bytes(4, "big")
        out += self.addr
        out += self.scopeid.to_bytes(4, "big")
        return out

    def __eq__(self, other) -> bool:
        return (
            isinstance(other, SockaddrIn6)
            and self.addr == other.addr
            and self.port == other.port
            and self.flowinfo == other.flowinfo
            and self.scopeid == other.scopeid
        )

    def __hash__(self) -> int:
        return hash((self.addr, self.port, self.flowinfo, self.scopeid))

    def __repr__(self) -> str:
        fields = [self.addr[2 * i] << 8 + self.addr[2 * i + 1] for i in range(0, 8)]
        field_str = ":".join(map(lambda x: f"{x:04x}", fields))
        return f"AF_INET6:{field_str}:{self.port}"


__all__ = ["Sockaddr", "SockaddrUn", "SockaddrIn", "SockaddrIn6"]
