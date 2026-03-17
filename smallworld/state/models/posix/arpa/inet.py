from ..... import emulators
from .....platforms import Byteorder
from ...cstd import ArgumentType, CStdModel


class Htons(CStdModel):
    name = "htons"

    # uint16_t htons(uint16_t)
    argument_types = [ArgumentType.UINT]
    return_type = ArgumentType.UINT

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        arg = self.get_arg1(emulator)

        assert isinstance(arg, int)

        if self.platform.byteorder == Byteorder.LITTLE:
            # Convert little to big endian
            arg = ((arg & 0xFF) << 8) | ((arg & 0xFF00) >> 8)

        self.set_return_value(emulator, arg)


class Ntohs(Htons):
    name = "ntohs"
    # On standard-endian systems, htons and ntohs are the same operation.


class Htonl(CStdModel):
    name = "htons"

    # uint32_t htons(uint32_t)
    argument_types = [ArgumentType.UINT]
    return_type = ArgumentType.UINT

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        arg = self.get_arg1(emulator)

        assert isinstance(arg, int)

        if self.platform.byteorder == Byteorder.LITTLE:
            # Convert little to big endian
            arg = (
                ((arg & 0x000000FF) << 24)
                | ((arg & 0x0000FF00) << 8)
                | ((arg & 0x00FF0000) >> 8)
                | ((arg & 0xFF000000) >> 24)
            )

        self.set_return_value(emulator, arg)


class Ntohl(Htonl):
    name = "ntohl"
    # On standard-endian systems, htonl and ntohl are the same operation


__all__ = ["Htons", "Ntohs", "Htonl", "Ntohl"]
