class FDIOError(Exception):
    """Exception indicating an error case in the file IO model"""

    pass


class FDIOOutOfFileStars(FDIOError):
    """Program tried to open more than the maximum number of FILE * handles

    Due to how the model builds FILE * handles, this is actually pretty small.
    """

    pass


class FDIOOutOfFDs(FDIOError):
    """Program tried to open more than the maximum number of file descriptors"""

    pass


class FDIOUnsupported(FDIOError):
    """Program tried to do something with an FD that it doesn't support"""

    pass


class FDIOInvalid(FDIOError):
    """Program passed an invalid integer fd or FILE * to the FDIO model"""

    pass


class FDIOUnsuported(FDIOError):
    """Program tried a forbidden operation on a file"""

    pass


class FDIOClosed(FDIOError):
    """Program tried to access a closed FD"""

    pass


class FDIOFSError(FDIOError):
    """Program had a bad interaction with the modeled file system"""

    pass


class FDIOUnknownFile(FDIOFSError):
    """Program asked to open an unknown file"""

    pass


__all__ = [
    "FDIOError",
    "FDIOOutOfFileStars",
    "FDIOOutOfFDs",
    "FDIOInvalid",
    "FDIOUnsupported",
    "FDIOClosed",
    "FDIOFSError",
    "FDIOUnknownFile",
]
