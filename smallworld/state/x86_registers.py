import typing

from .state import Register


class X86MMRRegister(Register):
    """x86 Memory Management Register

    These things have a special internal format,
    represented by the 4-tuple (selector, base, limit, flags).

    Since all emulators that support these registers
    take a 4-tuple as input, it makes more sense for the Register itself
    to accept the 4-tuple than it does to force you to
    determine the arch-specific packing.
    """

    def set_content(self, content: typing.Optional[typing.Any]):
        if content is not None:
            if (
                not isinstance(content, tuple)
                or len(content) != 4
                or not isinstance(content[0], int)
                or not isinstance(content[1], int)
                or not isinstance(content[2], int)
                or not isinstance(content[3], int)
            ):
                raise TypeError(
                    f"Expected Tuple[int, int, int, int], got {type(content)}"
                )
            # TODO: Please let these all be positive/unsigned.
        self._content = content

    def __str__(self):
        s = f"Reg({self.name},{self.size})="
        x = self.get_content()
        if x is None:
            s = s + "=None"
        else:
            s = s + ", ".join(map(lambda v: hex(v), x))
        return s
