import typing


class Executable:
    """An executable image and metadata storage class.

    Arguments:
        image (bytes): The actual bytes of the executable.
        type (str): Executable format ("blob", "PE", "ELF", etc.)
        arch (str): Architecture ("x86", "arm", etc.)
        mode (str): Architecture mode ("32", "64", etc.)
        base (int): Base address.
        entry (int): Execution entry address.
        exits (list): Exit addresses - used to determine when execution has
            terminated.
    """

    def __init__(
        self,
        image: bytes,
        type: typing.Optional[str] = None,
        arch: typing.Optional[str] = None,
        mode: typing.Optional[str] = None,
        base: typing.Optional[int] = None,
        entry: typing.Optional[int] = None,
        exits: typing.Optional[typing.Iterable[int]] = None,
    ):
        self.image = image
        self.type = type
        self.arch = arch
        self.mode = mode
        self.base = base
        self.entry = entry
        self.exits = exits or []

    @classmethod
    def from_filepath(cls, path: str, *args, **kwargs):
        with open(path, "rb") as f:
            image = f.read()

        return cls(image, *args, **kwargs)

    def __repr__(self) -> str:
        return f"Executable(type={self.type}, arch={self.arch}, mode={self.mode}, base={self.base}, entry={self.entry}, exits={self.exits})"
