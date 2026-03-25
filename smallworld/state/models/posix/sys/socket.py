import logging
import typing

from ..... import emulators
from .....platforms import Byteorder
from ...cstd import ArgumentType, CStdModel
from ...filedesc import FDIOError, FileDescriptorManager
from ..filedesc import POSIXFileDescriptorManager, Sockaddr, SocketIO

logger = logging.getLogger(__name__)


class FDModel(CStdModel):
    def __init__(self, address: int):
        super().__init__(address)

        fdmgr = FileDescriptorManager.for_platform(self.platform, self.abi)
        assert isinstance(fdmgr, POSIXFileDescriptorManager)

        self._fdmgr: POSIXFileDescriptorManager = fdmgr


class Accept(FDModel):
    name = "accept"

    # int accept(int, struct sockaddr *, socklen_ *)
    argument_types = [ArgumentType.INT, ArgumentType.POINTER, ArgumentType.POINTER]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        fd = self.get_arg1(emulator)
        addr = self.get_arg2(emulator)
        addrlen = self.get_arg3(emulator)

        assert isinstance(fd, int)
        assert isinstance(addr, int)
        assert isinstance(addrlen, int)

        try:
            connfd, connsock = self._fdmgr.accept(fd)
        except FDIOError:
            self.set_return_value(emulator, -1)
            return

        byteorder: typing.Literal["big", "little"]
        if self.platform.byteorder == Byteorder.BIG:
            byteorder = "big"
        else:
            byteorder = "little"

        # This should be guaranteed by accept()
        assert connsock.peername is not None

        if addr != 0:
            emulator.write_memory(addr, connsock.peername.to_bytes(byteorder))
        if addrlen != 0:
            emulator.write_memory(
                addrlen, connsock.peername.size.to_bytes(4, byteorder)
            )

        self.set_return_value(emulator, connfd)


class Bind(FDModel):
    name = "bind"

    # int bind(int, const struct sockaddr *, socklen_t)
    argument_types = [ArgumentType.INT, ArgumentType.POINTER, ArgumentType.INT]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        fd = self.get_arg1(emulator)
        addr = self.get_arg2(emulator)
        addrlen = self.get_arg3(emulator)

        assert isinstance(fd, int)
        assert isinstance(addr, int)
        assert isinstance(addrlen, int)

        addr_bytes = emulator.read_memory(addr, addrlen)

        try:
            self._fdmgr.bind(fd, addr_bytes)
        except FDIOError:
            self.set_return_value(emulator, -1)
            return

        self.set_return_value(emulator, 0)


class Connect(FDModel):
    name = "connect"

    # int connect(int, const struct sockaddr *, socklen_t)
    argument_types = [ArgumentType.INT, ArgumentType.POINTER, ArgumentType.INT]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        fd = self.get_arg1(emulator)
        addr = self.get_arg2(emulator)
        addrlen = self.get_arg3(emulator)

        assert isinstance(fd, int)
        assert isinstance(addr, int)
        assert isinstance(addrlen, int)

        addr_bytes = emulator.read_memory(addr, addrlen)

        try:
            self._fdmgr.connect(fd, addr_bytes)
        except FDIOError:
            self.set_return_value(emulator, -1)
            return

        self.set_return_value(emulator, 0)


class Getpeername(FDModel):
    name = "getpeername"

    # int getpeername(int, struct sockaddr *, socklen_t *)
    argument_types = [ArgumentType.INT, ArgumentType.POINTER, ArgumentType.POINTER]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        fd = self.get_arg1(emulator)
        addr = self.get_arg2(emulator)
        addrlen = self.get_arg3(emulator)

        assert isinstance(fd, int)
        assert isinstance(addr, int)
        assert isinstance(addrlen, int)

        try:
            socket = self._fdmgr.get_fd(fd)
        except FDIOError:
            self.set_return_value(emulator, -1)
            return

        if not isinstance(socket, SocketIO):
            self.set_return_value(emulator, -1)
            return

        if socket.peername is None:
            # TODO: I don't think this is accurate, but I'm not sure.
            self.set_return_value(emulator, -1)
            return

        byteorder: typing.Literal["big", "little"]
        if self.platform.byteorder == Byteorder.BIG:
            byteorder = "big"
        else:
            byteorder = "little"

        emulator.write_memory(addr, socket.peername.to_bytes(byteorder))
        emulator.write_memory(addrlen, socket.peername.size.to_bytes(4, byteorder))

        self.set_return_value(emulator, 0)


class Getsockname(FDModel):
    name = "getsockname"

    # int getsockname(int, struct sockaddr *, socklen_ *)
    argument_types = [ArgumentType.INT, ArgumentType.POINTER, ArgumentType.POINTER]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        fd = self.get_arg1(emulator)
        addr = self.get_arg2(emulator)
        addrlen = self.get_arg3(emulator)

        assert isinstance(fd, int)
        assert isinstance(addr, int)
        assert isinstance(addrlen, int)

        try:
            socket = self._fdmgr.get_fd(fd)
        except FDIOError:
            self.set_return_value(emulator, -1)
            return

        if not isinstance(socket, SocketIO):
            self.set_return_value(emulator, -1)
            return

        if socket.sockname is None:
            # TODO: I don't think this is accurate, but I'm not sure.
            self.set_return_value(emulator, -1)
            return

        byteorder: typing.Literal["big", "little"]
        if self.platform.byteorder == Byteorder.BIG:
            byteorder = "big"
        else:
            byteorder = "little"

        emulator.write_memory(addr, socket.sockname.to_bytes(byteorder))
        emulator.write_memory(addrlen, socket.sockname.size.to_bytes(4, byteorder))

        self.set_return_value(emulator, 0)


class Getsockopt(FDModel):
    name = "getsockopt"

    # int getsockopt(int, int, int, void *, socklen_t *)
    argument_types = [
        ArgumentType.INT,
        ArgumentType.INT,
        ArgumentType.INT,
        ArgumentType.POINTER,
        ArgumentType.POINTER,
    ]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        raise NotImplementedError(f"{self.name}() is not implemented")


class Listen(FDModel):
    name = "listen"

    # int listen(int, int)
    argument_types = [ArgumentType.INT, ArgumentType.INT]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        fd = self.get_arg1(emulator)
        assert isinstance(fd, int)

        try:
            socket = self._fdmgr.get_fd(fd)
        except FDIOError:
            self.set_return_value(emulator, -1)
            return

        if not isinstance(socket, SocketIO):
            self.set_return_value(emulator, -1)
            return

        self.set_return_value(emulator, 0)


class Recv(FDModel):
    name = "recv"

    # ssize_t recv(int, void *, size_t, int)
    argument_types = [
        ArgumentType.INT,
        ArgumentType.POINTER,
        ArgumentType.SIZE_T,
        ArgumentType.INT,
    ]
    return_type = ArgumentType.SSIZE_T

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        fd = self.get_arg1(emulator)
        buf = self.get_arg2(emulator)
        buflen = self.get_arg3(emulator)
        flags = self.get_arg4(emulator)

        assert isinstance(fd, int)
        assert isinstance(buf, int)
        assert isinstance(buflen, int)
        assert isinstance(flags, int)

        try:
            socket = self._fdmgr.get_fd(fd)
        except FDIOError:
            self.set_return_value(emulator, -1)
            return

        if not isinstance(socket, SocketIO):
            self.set_return_value(emulator, -1)
            return

        peek = (flags & 0x2) != 0
        trunc = (flags & 0x20) != 0

        data, peername = socket.recv(peek)
        emulator.write_memory(buf, data[0:buflen])

        if trunc:
            self.set_return_value(emulator, len(data))
        else:
            self.set_return_value(emulator, min(len(data), buflen))


class Recvfrom(FDModel):
    name = "recvfrom"

    # ssize_t recv(int, void *, size_t, int, struct sockaddr *, socklen_t *)
    argument_types = [
        ArgumentType.INT,
        ArgumentType.POINTER,
        ArgumentType.SIZE_T,
        ArgumentType.INT,
        ArgumentType.POINTER,
        ArgumentType.POINTER,
    ]
    return_type = ArgumentType.SSIZE_T

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        fd = self.get_arg1(emulator)
        buf = self.get_arg2(emulator)
        buflen = self.get_arg3(emulator)
        flags = self.get_arg4(emulator)
        addr = self.get_arg5(emulator)
        addrlen = self.get_arg6(emulator)

        assert isinstance(fd, int)
        assert isinstance(buf, int)
        assert isinstance(buflen, int)
        assert isinstance(flags, int)
        assert isinstance(addr, int)
        assert isinstance(addrlen, int)

        try:
            socket = self._fdmgr.get_fd(fd)
        except FDIOError:
            self.set_return_value(emulator, -1)
            return

        if not isinstance(socket, SocketIO):
            self.set_return_value(emulator, -1)
            return

        peek = (flags & 0x2) != 0
        trunc = (flags & 0x20) != 0

        data, peername = socket.recv(peek)
        emulator.write_memory(buf, data[0:buflen])

        byteorder: typing.Literal["big", "little"]
        if self.platform.byteorder == Byteorder.BIG:
            byteorder = "big"
        else:
            byteorder = "little"

        emulator.write_memory(addr, peername.to_bytes(byteorder))
        emulator.write_memory(addr, peername.size.to_bytes(4, byteorder))

        if trunc:
            self.set_return_value(emulator, len(data))
        else:
            self.set_return_value(emulator, min(len(data), buflen))


class Recvmsg(FDModel):
    name = "recvmsg"

    # ssize_t recvmsg(int, struct msghdr *, flags)
    argument_types = [ArgumentType.INT, ArgumentType.POINTER, ArgumentType.INT]
    return_type = ArgumentType.SSIZE_T

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        raise NotImplementedError(f"{self.name}() is not implemented")


class Send(FDModel):
    name = "send"

    # ssize_t send(int, const void *, size_t, int)
    argument_types = [
        ArgumentType.INT,
        ArgumentType.POINTER,
        ArgumentType.SIZE_T,
        ArgumentType.INT,
    ]
    return_type = ArgumentType.SSIZE_T

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        fd = self.get_arg1(emulator)
        buf = self.get_arg2(emulator)
        buflen = self.get_arg3(emulator)
        flags = self.get_arg4(emulator)

        assert isinstance(fd, int)
        assert isinstance(buf, int)
        assert isinstance(buflen, int)
        assert isinstance(flags, int)

        try:
            socket = self._fdmgr.get_fd(fd)
        except FDIOError:
            self.set_return_value(emulator, -1)
            return

        if not isinstance(socket, SocketIO):
            self.set_return_value(emulator, -1)
            return

        if socket.peername is None:
            self.set_return_value(emulator, -1)
            return

        data = emulator.read_memory(buf, buflen)

        try:
            socket.send(data, socket.peername)
        except FDIOError:
            self.set_return_value(emulator, -1)
            return

        self.set_return_value(emulator, len(data))


class Sendmsg(FDModel):
    name = "sendmsg"

    # ssize_t sendmsg(int, const struct msghdr *, int)
    argument_types = [ArgumentType.INT, ArgumentType.POINTER, ArgumentType.INT]
    return_type = ArgumentType.SSIZE_T

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        raise NotImplementedError(f"{self.name}() is not implemented")


class Sendto(FDModel):
    name = "sendto"

    # ssize_t sendto(int, void *, size_t, int, struct sockaddr *, socklen_t)
    argument_types = [
        ArgumentType.INT,
        ArgumentType.POINTER,
        ArgumentType.SIZE_T,
        ArgumentType.INT,
        ArgumentType.POINTER,
        ArgumentType.INT,
    ]
    return_type = ArgumentType.SSIZE_T

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        fd = self.get_arg1(emulator)
        buf = self.get_arg2(emulator)
        buflen = self.get_arg3(emulator)
        flags = self.get_arg4(emulator)
        addr = self.get_arg5(emulator)
        addrlen = self.get_arg6(emulator)

        assert isinstance(fd, int)
        assert isinstance(buf, int)
        assert isinstance(buflen, int)
        assert isinstance(flags, int)
        assert isinstance(addr, int)
        assert isinstance(addrlen, int)

        try:
            socket = self._fdmgr.get_fd(fd)
        except FDIOError:
            self.set_return_value(emulator, -1)
            return

        if not isinstance(socket, SocketIO):
            self.set_return_value(emulator, -1)
            return

        data = emulator.read_memory(buf, buflen)

        byteorder: typing.Literal["big", "little"]
        if self.platform.byteorder == Byteorder.BIG:
            byteorder = "big"
        else:
            byteorder = "little"

        addr_bytes = emulator.read_memory(addr, addrlen)
        peername = Sockaddr.for_family(socket.domain)
        peername.from_bytes(addr_bytes, byteorder)

        try:
            socket.send(data, peername)
        except FDIOError:
            self.set_return_value(emulator, -1)
            return

        self.set_return_value(emulator, len(data))


class Setsockopt(FDModel):
    name = "setsockopt"

    # int setsockopt(int, int, int, const void *, socklen_t)
    argument_types = [
        ArgumentType.INT,
        ArgumentType.INT,
        ArgumentType.INT,
        ArgumentType.POINTER,
        ArgumentType.INT,
    ]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        fd = self.get_arg1(emulator)
        level = self.get_arg2(emulator)
        optname = self.get_arg3(emulator)
        optval = self.get_arg4(emulator)
        optlen = self.get_arg5(emulator)

        assert isinstance(fd, int)
        assert isinstance(level, int)
        assert isinstance(optname, int)
        assert isinstance(optval, int)
        assert isinstance(optlen, int)

        try:
            socket = self._fdmgr.get_fd(fd)
        except FDIOError:
            self.set_return_value(emulator, -1)
            return

        if not isinstance(socket, SocketIO):
            self.set_return_value(emulator, -1)
            return

        logger.warning(
            "Called setsockopt({fd}, {level}, {optname}, {hex(optval)}, {optlen}); Doing nothing"
        )
        self.set_return_value(emulator, 0)


class Shutdown(FDModel):
    name = "shutdown"

    # int shutdown(int, int)
    argument_types = [ArgumentType.INT, ArgumentType.INT]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        fd = self.get_arg1(emulator)
        how = self.get_arg2(emulator)
        assert isinstance(fd, int)
        assert isinstance(how, int)

        try:
            socket = self._fdmgr.get_fd(fd)
        except FDIOError:
            self.set_return_value(emulator, -1)
            return

        if not isinstance(socket, SocketIO):
            self.set_return_value(emulator, -1)
            return

        if how == 0:
            # SHUT_RD
            socket._readable = False
        elif how == 1:
            # SHUT_WR
            socket._writable = False
        elif how == 2:
            # SHUT_RDWR
            socket._readable = False
            socket._writable = False
        else:
            self.set_return_value(emulator, -1)
            return
        self.set_return_value(emulator, 0)


class Socket(FDModel):
    name = "socket"

    # int socket(int, int, int)
    argument_types = [ArgumentType.INT, ArgumentType.INT, ArgumentType.INT]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        domain = self.get_arg1(emulator)
        type = self.get_arg2(emulator)
        protocol = self.get_arg3(emulator)

        assert isinstance(domain, int)
        assert isinstance(type, int)
        assert isinstance(protocol, int)

        try:
            fd = self._fdmgr.socket(domain, type, protocol)
        except FDIOError:
            self.set_return_value(emulator, -1)
            return

        self.set_return_value(emulator, fd)


class Socketpair(FDModel):
    name = "socketpair"

    # int socketpair(int, int, int[2])
    argument_types = [ArgumentType.INT, ArgumentType.INT, ArgumentType.POINTER]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        raise NotImplementedError(f"{self.name}() is not implemented")


__all__ = [
    "Accept",
    "Bind",
    "Connect",
    "Getpeername",
    "Getsockname",
    "Getsockopt",
    "Listen",
    "Recv",
    "Recvfrom",
    "Recvmsg",
    "Send",
    "Sendmsg",
    "Sendto",
    "Setsockopt",
    "Shutdown",
    "Socket",
    "Socketpair",
]
