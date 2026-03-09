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


class FDIOInvalid(FDIOError):
    """Program passed an invalid integer fd or FILE * to the FDIO model"""

    pass


class FDIOAccess(FDIOError):
    """Program tried a forbidden operation on a file"""

    pass


class FDIOClosed(FDIOAccess):
    """Program tried to access a closed FD"""

    pass


class FDIOBadRead(FDIOAccess):
    """Program tried to read an unreadable file"""

    pass


class FDIOBadSeek(FDIOAccess):
    """Program tried to seek an unseekable file"""

    pass


class FDIOBadTruncate(FDIOAccess):
    """Program tried to truncate an untruncatable file"""

    pass


class FDIOBadWrite(FDIOAccess):
    """Program tried to write an unwritable file"""

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
    "FDIOAccess",
    "FDIOClosed",
    "FDIOBadRead",
    "FDIOBadSeek",
    "FDIOBadTruncate",
    "FDIOBadWrite",
    "FDIOFSError",
    "FDIOUnknownFile",
]
