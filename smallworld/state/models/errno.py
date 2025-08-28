import abc

from ... import utils
from ...platforms import ABI, Architecture, Byteorder, Platform


class ErrnoResolver(metaclass=abc.ABCMeta):
    """Errno resolver

    For some UNGODLY REASON,
    the System V ABIs can't agree on errno values across platforms.
    """

    @property
    @abc.abstractmethod
    def platform(self) -> Platform:
        """The platform this errno resolver supports"""
        raise NotImplementedError()

    @property
    @abc.abstractmethod
    def abi(self) -> ABI:
        """The ABI this errno resolver supports"""
        raise NotImplementedError()

    # These are the numbers from asm-generic.
    # MOST architectures use these... (MIPS!!!)
    errno_to_label = {
        1: "EPERM",
        2: "ENOENT",
        3: "ESRCH",
        4: "EINTR",
        5: "EIO",
        6: "ENXIO",
        7: "E2BIG",
        8: "ENOEXEC",
        9: "EBADF",
        10: "ECHILD",
        11: "EAGAIN",
        12: "ENOMEM",
        13: "EACCES",
        14: "EFAULT",
        15: "ENOTBLK",
        16: "EBUSY",
        17: "EEXIST",
        18: "EXDEV",
        19: "ENODEV",
        20: "ENOTDIR",
        21: "EISDIR",
        22: "EINVAL",
        23: "ENFILE",
        24: "EMFILE",
        25: "ENOTTY",
        26: "ETXTBSY",
        27: "EFBIG",
        28: "ENOSPC",
        29: "ESPIPE",
        30: "EROFS",
        31: "EMLINK",
        32: "EPIPE",
        33: "EDOM",
        34: "ERANGE",
        35: "EDEADLK",
        36: "ENAMETOOLONG",
        37: "ENOLCK",
        38: "ENOSYS",
        39: "ENOTEMPTY",
        40: "ELOOP",
        42: "ENOMSG",
        43: "EIDRM",
        44: "ECHRNG",
        45: "EL2NSYNC",
        46: "EL3HLT",
        47: "EL3RST",
        48: "ELNRNG",
        49: "EUNATCH",
        50: "ENOCSI",
        51: "EL2HLT",
        52: "EBADE",
        53: "EBADR",
        54: "EXFULL",
        55: "ENOANO",
        56: "EBADRQC",
        57: "EBADSLT",
        59: "EBFONT",
        60: "ENOSTR",
        61: "ENODATA",
        62: "ETIME",
        63: "ENOSR",
        64: "ENONET",
        65: "ENOPKG",
        66: "EREMOTE",
        67: "ENOLINK",
        68: "EADV",
        69: "ESRMNT",
        70: "ECOMM",
        71: "EPROTO",
        72: "EMULTIHOP",
        73: "EDOTDOT",
        74: "EBADMSG",
        75: "EOVERFLOW",
        76: "ENOTUNIQ",
        77: "EBADFD",
        78: "EREMCHG",
        79: "ELIBACC",
        80: "ELIBBAD",
        81: "ELIBSCN",
        82: "ELIBMAX",
        83: "ELIBEXEC",
        84: "EILSEQ",
        85: "ERESTART",
        86: "ESTRPIPE",
        87: "EUSERS",
        88: "ENOTSOCK",
        89: "EDESTADDRREQ",
        90: "EMSGSIZE",
        91: "EPROTOTYPE",
        92: "ENOPROTOOPT",
        93: "EPROTONOSUPPORT",
        94: "ESOCKTNOSUPPORT",
        95: "EOPNOTSUPP",
        96: "EPFNOSUPPORT",
        97: "EAFNOSUPPORT",
        98: "EADDRINUSE",
        99: "EADDRNOTAVAIL",
        100: "ENETDOWN",
        101: "ENETUNREACH",
        102: "ENETRESET",
        103: "ECONNABORTED",
        104: "ECONNRESET",
        105: "ENOBUFS",
        106: "EISCONN",
        107: "ENOTCONN",
        108: "ESHUTDOWN",
        109: "ETOOMANYREFS",
        110: "ETIMEDOUT",
        111: "ECONNREFUSED",
        112: "EHOSTDOWN",
        113: "EHOSTUNREACH",
        114: "EALREADY",
        115: "EINPROGRESS",
        116: "ESTALE",
        117: "EUCLEAN",
        118: "ENOTNAM",
        119: "ENAVAIL",
        120: "EISNAM",
        121: "EREMOTEIO",
        122: "EDQUOT",
        123: "ENOMEDIUM",
        124: "EMEDIUMTYPE",
        125: "ECANCELED",
        126: "ENOKEY",
        127: "EKEYEXPIRED",
        128: "EKEYREVOKED",
        129: "EKEYREJECTED",
        130: "EOWNERDEAD",
        131: "ENOTRECOVERABLE",
        132: "ERFKILL",
        133: "EHWPOISON",
    }

    label_to_description = {
        "EPERM": "Operation not permitted",
        "ENOENT": "No such file or directory",
        "ESRCH": "No such process",
        "EINTR": "Interrupted system call",
        "EIO": "Input/output error",
        "ENXIO": "No such device or address",
        "E2BIG": "Argument list too long",
        "ENOEXEC": "Exec format error",
        "EBADF": "Bad file descriptor",
        "ECHILD": "No child processes",
        "EAGAIN": "Resource temporarily unavailable",
        "ENOMEM": "Cannot allocate memory",
        "EACCES": "Permission denied",
        "EFAULT": "Bad address",
        "ENOTBLK": "Block device required",
        "EBUSY": "Device or resource busy",
        "EEXIST": "File exists",
        "EXDEV": "Invalid cross-device link",
        "ENODEV": "No such device",
        "ENOTDIR": "Not a directory",
        "EISDIR": "Is a directory",
        "EINVAL": "Invalid argument",
        "ENFILE": "Too many open files in system",
        "EMFILE": "Too many open files",
        "ENOTTY": "Inappropriate ioctl for device",
        "ETXTBSY": "Text file busy",
        "EFBIG": "File too large",
        "ENOSPC": "No space left on device",
        "ESPIPE": "Illegal seek",
        "EROFS": "Read-only file system",
        "EMLINK": "Too many links",
        "EPIPE": "Broken pipe",
        "EDOM": "Numerical argument out of domain",
        "ERANGE": "Numerical result out of range",
        "EDEADLK": "Resource deadlock avoided",
        "ENAMETOOLONG": "File name too long",
        "ENOLCK": "No locks available",
        "ENOSYS": "Function not implemented",
        "ENOTEMPTY": "Directory not empty",
        "ELOOP": "Too many levels of symbolic links",
        "EWOULDBLOCK": "Resource temporarily unavailable",
        "ENOMSG": "No message of desired type",
        "EIDRM": "Identifier removed",
        "ECHRNG": "Channel number out of range",
        "EL2NSYNC": "Level 2 not synchronized",
        "EL3HLT": "Level 3 halted",
        "EL3RST": "Level 3 reset",
        "ELNRNG": "Link number out of range",
        "EUNATCH": "Protocol driver not attached",
        "ENOCSI": "No CSI structure available",
        "EL2HLT": "Level 2 halted",
        "EBADE": "Invalid exchange",
        "EBADR": "Invalid request descriptor",
        "EXFULL": "Exchange full",
        "ENOANO": "No anode",
        "EBADRQC": "Invalid request code",
        "EBADSLT": "Invalid slot",
        "EDEADLCK": "Resource deadlock avoided",
        "EDEADLOCK": "Resource deadlock avoided",
        "EBFONT": "Bad font file format",
        "ENOSTR": "Device not a stream",
        "ENODATA": "No data available",
        "ETIME": "Timer expired",
        "ENOSR": "Out of streams resources",
        "ENONET": "Machine is not on the network",
        "ENOPKG": "Package not installed",
        "EREMOTE": "Object is remote",
        "ENOLINK": "Link has been severed",
        "EADV": "Advertise error",
        "ESRMNT": "Srmount error",
        "ECOMM": "Communication error on send",
        "EPROTO": "Protocol error",
        "EMULTIHOP": "Multihop attempted",
        "EDOTDOT": "RFS specific error",
        "EBADMSG": "Bad message",
        "EOVERFLOW": "Value too large for defined data type",
        "ENOTUNIQ": "Name not unique on network",
        "EBADFD": "File descriptor in bad state",
        "EREMCHG": "Remote address changed",
        "ELIBACC": "Can not access a needed shared library",
        "ELIBBAD": "Accessing a corrupted shared library",
        "ELIBSCN": ".lib section in a.out corrupted",
        "ELIBMAX": "Attempting to link in too many shared libraries",
        "ELIBEXEC": "Cannot exec a shared library directly",
        "EILSEQ": "Invalid or incomplete multibyte or wide character",
        "ERESTART": "Interrupted system call should be restarted",
        "ESTRPIPE": "Streams pipe error",
        "EUSERS": "Too many users",
        "ENOTSOCK": "Socket operation on non-socket",
        "EDESTADDRREQ": "Destination address required",
        "EMSGSIZE": "Message too long",
        "EPROTOTYPE": "Protocol wrong type for socket",
        "ENOPROTOOPT": "Protocol not available",
        "EPROTONOSUPPORT": "Protocol not supported",
        "ESOCKTNOSUPPORT": "Socket type not supported",
        "EOPNOTSUPP": "Operation not supported",
        "EPFNOSUPPORT": "Protocol family not supported",
        "EAFNOSUPPORT": "Address family not supported by protocol",
        "EADDRINUSE": "Address already in use",
        "EADDRNOTAVAIL": "Cannot assign requested address",
        "ENETDOWN": "Network is down",
        "ENETUNREACH": "Network is unreachable",
        "ENETRESET": "Network dropped connection on reset",
        "ECONNABORTED": "Software caused connection abort",
        "ECONNRESET": "Connection reset by peer",
        "ENOBUFS": "No buffer space available",
        "EISCONN": "Transport endpoint is already connected",
        "ENOTCONN": "Transport endpoint is not connected",
        "ESHUTDOWN": "Cannot send after transport endpoint shutdown",
        "ETOOMANYREFS": "Too many references: cannot splice",
        "ETIMEDOUT": "Connection timed out",
        "ECONNREFUSED": "Connection refused",
        "EHOSTDOWN": "Host is down",
        "EHOSTUNREACH": "No route to host",
        "EALREADY": "Operation already in progress",
        "EINPROGRESS": "Operation now in progress",
        "ESTALE": "Stale file handle",
        "EUCLEAN": "Structure needs cleaning",
        "ENOTNAM": "Not a XENIX named type file",
        "ENAVAIL": "No XENIX semaphores available",
        "EISNAM": "Is a named type file",
        "EREMOTEIO": "Remote I/O error",
        "EDQUOT": "Disk quota exceeded",
        "ENOMEDIUM": "No medium found",
        "EMEDIUMTYPE": "Wrong medium type",
        "ECANCELED": "Operation canceled",
        "ENOKEY": "Required key not available",
        "EKEYEXPIRED": "Key has expired",
        "EKEYREVOKED": "Key has been revoked",
        "EKEYREJECTED": "Key was rejected by service",
        "EOWNERDEAD": "Owner died",
        "ENOTRECOVERABLE": "State not recoverable",
        "ERFKILL": "Operation not possible due to RF-kill",
        "EHWPOISON": "Memory page has hardware error",
        "ENOTSUP": "Operation not supported",
    }

    def get_label(self, errno: int) -> str:
        """Get the label for an errno by its number

        NOTE: Some numbers are tied to mulitple errors.
        This function will always return the same label
        for the same number.  No guarantees
        that it's the one you want in case of collision.

        This will raise an exception in case of an unknown number

        Arguments:
            errno: The error number

        Returns:
            A string containing the macro defined for that number
        """

        if errno not in self.errno_to_label:
            raise KeyError(f"Unknown errno {errno}")
        return self.errno_to_label[errno]

    def get_description(self, errno: int) -> str:
        """Get the descriptive text for an errno by its number

        NOTE: Some numbers are tied to mulitple errors.
        This function will always return the same description
        for the same number.  No guarantees
        that it's the one you want in case of collision.

        This will return the string "Unknown error {errno}"
        in case of an unknown number.

        Arguments:
            errno: The error number

        Returns:
            The descriptive text for this errno.
        """
        try:
            label = self.get_label(errno)
            if label not in self.label_to_description:
                return f"Unknown error {errno}"
            return self.label_to_description[label]
        except KeyError:
            return f"Unknown error {errno}"

    @classmethod
    def for_platform(cls, platform: Platform, abi: ABI) -> "ErrnoResolver":
        """Instantiate an errno resolver by platform and ABI.

        Arguments:
            platform: The platform for which this resolver is defined
            abi: The ABI for which this resolver is defined

        Returns:
            The errno resolver for this platform and ABI
        """
        try:
            return utils.find_subclass(
                cls, lambda x: x.platform == platform and x.abi == abi
            )
        except ValueError:
            raise ValueError(f"no errno resolver for {platform} with ABI '{abi}'")


class AArch64ErrnoResolver(ErrnoResolver):
    platform = Platform(Architecture.AARCH64, Byteorder.LITTLE)
    abi = ABI.SYSTEMV
    # aarch64 uses generic errno


class AMD64ErrnoResolver(ErrnoResolver):
    platform = Platform(Architecture.X86_64, Byteorder.LITTLE)
    abi = ABI.SYSTEMV
    # amd64 uses generic errno


class ArmELErrnoResolver(ErrnoResolver):
    platform = Platform(Architecture.ARM_V5T, Byteorder.LITTLE)
    abi = ABI.SYSTEMV
    # armel uses generic errno


class ArmHFErrnoResolver(ErrnoResolver):
    platform = Platform(Architecture.ARM_V7A, Byteorder.LITTLE)
    abi = ABI.SYSTEMV
    # armhf uses generic errno


class I386ErrnoResolver(ErrnoResolver):
    platform = Platform(Architecture.X86_32, Byteorder.LITTLE)
    abi = ABI.SYSTEMV
    # i386 uses generic errno


class MIPSErrnoResolver(ErrnoResolver):
    abi = ABI.SYSTEMV
    # MIPS Absolutely doesn't use generic errno
    errno_to_label = {
        1: "EPERM",
        2: "ENOENT",
        3: "ESRCH",
        4: "EINTR",
        5: "EIO",
        6: "ENXIO",
        7: "E2BIG",
        8: "ENOEXEC",
        9: "EBADF",
        10: "ECHILD",
        11: "EAGAIN",
        12: "ENOMEM",
        13: "EACCES",
        14: "EFAULT",
        15: "ENOTBLK",
        16: "EBUSY",
        17: "EEXIST",
        18: "EXDEV",
        19: "ENODEV",
        20: "ENOTDIR",
        21: "EISDIR",
        22: "EINVAL",
        23: "ENFILE",
        24: "EMFILE",
        25: "ENOTTY",
        26: "ETXTBSY",
        27: "EFBIG",
        28: "ENOSPC",
        29: "ESPIPE",
        30: "EROFS",
        31: "EMLINK",
        32: "EPIPE",
        33: "EDOM",
        34: "ERANGE",
        35: "ENOMSG",
        36: "EIDRM",
        37: "ECHRNG",
        38: "EL2NSYNC",
        39: "EL3HLT",
        40: "EL3RST",
        41: "ELNRNG",
        42: "EUNATCH",
        43: "ENOCSI",
        44: "EL2HLT",
        45: "EDEADLK",
        46: "ENOLCK",
        50: "EBADE",
        51: "EBADR",
        52: "EXFULL",
        53: "ENOANO",
        54: "EBADRQC",
        55: "EBADSLT",
        56: "EDEADLOCK",
        59: "EBFONT",
        60: "ENOSTR",
        61: "ENODATA",
        62: "ETIME",
        63: "ENOSR",
        64: "ENONET",
        65: "ENOPKG",
        66: "EREMOTE",
        67: "ENOLINK",
        68: "EADV",
        69: "ESRMNT",
        70: "ECOMM",
        71: "EPROTO",
        73: "EDOTDOT",
        74: "EMULTIHOP",
        77: "EBADMSG",
        78: "ENAMETOOLONG",
        79: "EOVERFLOW",
        80: "ENOTUNIQ",
        81: "EBADFD",
        82: "EREMCHG",
        83: "ELIBACC",
        84: "ELIBBAD",
        85: "ELIBSCN",
        86: "ELIBMAX",
        87: "ELIBEXEC",
        88: "EILSEQ",
        89: "ENOSYS",
        90: "ELOOP",
        91: "ERESTART",
        92: "ESTRPIPE",
        93: "ENOTEMPTY",
        94: "EUSERS",
        95: "ENOTSOCK",
        96: "EDESTADDRREQ",
        97: "EMSGSIZE",
        98: "EPROTOTYPE",
        99: "ENOPROTOOPT",
        120: "EPROTONOSUPPORT",
        121: "ESOCKTNOSUPPORT",
        122: "EOPNOTSUPP",
        123: "EPFNOSUPPORT",
        124: "EAFNOSUPPORT",
        125: "EADDRINUSE",
        126: "EADDRNOTAVAIL",
        127: "ENETDOWN",
        128: "ENETUNREACH",
        129: "ENETRESET",
        130: "ECONNABORTED",
        131: "ECONNRESET",
        132: "ENOBUFS",
        133: "EISCONN",
        134: "ENOTCONN",
        135: "EUCLEAN",
        137: "ENOTNAM",
        138: "ENAVAIL",
        139: "EISNAM",
        140: "EREMOTEIO",
        141: "EINIT",
        142: "EREMDEV",
        143: "ESHUTDOWN",
        144: "ETOOMANYREFS",
        145: "ETIMEDOUT",
        146: "ECONNREFUSED",
        147: "EHOSTDOWN",
        148: "EHOSTUNREACH",
        149: "EALREADY",
        150: "EINPROGRESS",
        151: "ESTALE",
        158: "ECANCELED",
        159: "ENOMEDIUM",
        160: "EMEDIUMTYPE",
        161: "ENOKEY",
        162: "EKEYEXPIRED",
        163: "EKEYREVOKED",
        164: "EKEYREJECTED",
        165: "EOWNERDEAD",
        166: "ENOTRECOVERABLE",
        167: "ERFKILL",
        168: "EHWPOISON",
        1133: "EDQUOT",
    }


class MIPSBEErrnoResolver(MIPSErrnoResolver):
    platform = Platform(Architecture.MIPS32, Byteorder.BIG)
    # mips uses the MIPS errno list


class MIPSELErrnoResolver(MIPSErrnoResolver):
    platform = Platform(Architecture.MIPS32, Byteorder.LITTLE)
    # mipsel uses the MIPS errno list


class MIPS64BEErrnoResolver(MIPSErrnoResolver):
    platform = Platform(Architecture.MIPS64, Byteorder.BIG)
    # mips64 uses the MIPS errno list


class MIPS64ELErrnoResolver(MIPSErrnoResolver):
    platform = Platform(Architecture.MIPS64, Byteorder.LITTLE)
    # mips64el uses the MIPS errno list


class PowerPCErrnoResolver(ErrnoResolver):
    platform = Platform(Architecture.POWERPC32, Byteorder.BIG)
    abi = ABI.SYSTEMV

    # The ppc errno list is almost identical to generic,
    # except that EDEADLOCK is different.
    #
    # In generic, it's been aliased to EDEADLK,
    # although the ordering of the header suggests that at one time
    # it looked like it does here.
    errno_to_label = ErrnoResolver.errno_to_label | {35: "EDEADLCK", 58: "EDEADLOCK"}


class RiscV64ErrnoResolver(ErrnoResolver):
    platform = Platform(Architecture.RISCV64, Byteorder.LITTLE)
    abi = ABI.SYSTEMV
    # riscv64 uses the generic errno list


__all__ = ["ErrnoResolver"]
