from .... import emulators
from ..c99.utils import _emu_strlen
from ..cstd import ArgumentType, CStdModel


class Basename(CStdModel):
    name = "basename"

    # char *basename(char *path);
    argument_types = [ArgumentType.POINTER]
    return_type = ArgumentType.POINTER

    def __init__(self, address: int):
        super().__init__(address)

        # Override this to change how you parse paths
        self.separator = b"/"

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        pathptr = self.get_arg1(emulator)

        assert isinstance(pathptr, int)

        # NOTE: This is the POSIX version of basename
        #
        # There is also a GNU version.
        # The main semantic difference is that the GNU version
        # will return an empty string on trailing separator,
        # or on the root path.
        #
        # The GNU version also always uses static memory, which is a problem

        if pathptr == 0:
            # Case: pathptr is NULL; return a static buffer containing '.'
            raise NotImplementedError("Requires a static buffer")

        pathlen = _emu_strlen(emulator, pathptr)
        path = emulator.read_memory(pathptr, pathlen)

        if path == self.separator:
            # Case: Path is '/': Return itself
            self.set_return_value(emulator, pathptr)
            return

        if path[-1] == self.separator[0]:
            # Case: Path ends in '/': Delete the trailing slash
            path = path[0:-2]
            emulator.write_memory(pathptr + pathlen - 1, b"\0")

        if self.separator not in path:
            # Case: no path separator: Return copy of path
            self.set_return_value(emulator, pathptr)
            return

        # Case: Path has a '/' in it: Return the trailing substring of path
        idx = path.rindex(self.separator)
        self.set_return_value(emulator, pathptr + idx + 1)


class Dirname(CStdModel):
    name = "dirname"

    # char *dirname(char *path);
    argument_types = [ArgumentType.POINTER]
    return_type = ArgumentType.POINTER

    def __init__(self, address: int):
        super().__init__(address)

        # Override this to change how you parse paths
        self.separator = b"/"

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        pathptr = self.get_arg1(emulator)

        assert isinstance(pathptr, int)

        if pathptr == 0:
            # Case: pathptr is NULL; return a static buffer containing '.'
            raise NotImplementedError("Requires a static buffer")

        pathlen = _emu_strlen(emulator, pathptr)
        path = emulator.read_memory(pathptr, pathlen)

        if path == self.separator:
            # Case: Path is '/': Return itself
            self.set_return_value(emulator, pathptr)
            return

        if self.separator not in path:
            # Case: No path separator; return '.'
            emulator.write_memory(pathptr, b".\0")
            self.set_return_value(emulator, pathptr)
            return

        # Case: Path has a '/' in it.  Replace it with \0 and return original pointer
        idx = path.rindex(self.separator)
        emulator.write_memory(pathptr + idx, b"\0")
        self.set_return_value(emulator, pathptr)


__all__ = ["Basename", "Dirname"]
