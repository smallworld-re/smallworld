from .... import emulators
from ..c99.utils import _emu_strlen
from ..cstd import ArgumentType, CStdModel


class Basename(CStdModel):
    name = "basename"

    # NOTE: There are two versions of basename().
    #
    # POSIX and GNU have competing specifications.
    # They have the following differences:
    #
    # - GNU always uses a static buffer for its returns
    # - GNU returns "" in case of trailing separators
    # - GNU returns "" in case of the root path

    # char *basename(char *path);
    argument_types = [ArgumentType.POINTER]
    return_type = ArgumentType.POINTER

    # Use the GNU memory semantics
    static_space_required = 0x1000

    def __init__(self, address: int):
        super().__init__(address)

        # Override this to change how you parse paths
        self.separator = b"/"

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        pathptr = self.get_arg1(emulator)

        assert isinstance(pathptr, int)

        # Not actually a loop; I just want to use break.
        while True:
            if pathptr == 0:
                # Case: pathptr is NULL; return a static buffer containing '.'
                path = b"."
                break

            pathlen = _emu_strlen(emulator, pathptr)
            path = emulator.read_memory(pathptr, pathlen)

            if path == self.separator:
                # Case: Path is the root path: Return itself
                break

            if path[-1] == self.separator[0]:
                # Case: Path ends in separator: Delete the trailing separator
                path = path[0:-1]

            if self.separator not in path:
                # Case: no path separator: Return copy of path
                break

            # Case: Path has a separator in it: Return the trailing substring of path
            idx = path.rindex(self.separator)
            path = path[idx + 1 :]
            break

        assert self.static_buffer_address is not None

        emulator.write_memory(self.static_buffer_address, path + b"\0")
        self.set_return_value(emulator, self.static_buffer_address)


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
            print("Root case")
            self.set_return_value(emulator, pathptr)
            return

        if self.separator not in path:
            # Case: No path separator; return '.'
            emulator.write_memory(pathptr, b".\0")
            self.set_return_value(emulator, pathptr)
            return

        if path[-1] == self.separator[0]:
            path = path[:-2]

        idx = path.rindex(self.separator)
        if idx == 0:
            # Case: Path's lowest '/' is the root path; return '/'
            emulator.write_memory(pathptr + idx + 1, b"\0")
        else:
            # Case: Path has a '/' in it.  Replace it with \0 and return original pointer
            emulator.write_memory(pathptr + idx, b"\0")
        self.set_return_value(emulator, pathptr)


__all__ = ["Basename", "Dirname"]
