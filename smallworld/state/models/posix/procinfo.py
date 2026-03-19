import typing


class ProcInfoManager:
    """Model of POSIX process state

    This collects a lot of information
    that doesn't really change unless the program specifically requests it to change.
    """

    _singleton: typing.Optional["ProcInfoManager"] = None

    def __init__(self):
        # Credentials information
        # Real user/group IDs
        self.uid: int = 0
        self.gid: int = 0
        # Effective user/group IDs
        self.euid: int = 0
        self.egid: int = 0
        # Saved user/group IDs
        self.suid: int = 0
        self.sgid: int = 0
        # Supplemental group IDs
        self.groups: typing.List[int] = []

        # Process ID information
        # Process ID
        self.pid: int = 0
        # Process group ID
        self.pgrp: int = 0
        # Parent process ID
        self.ppid: int = 0

        # Identifiers
        self.hostid: int = 0
        self.termid: bytes = b"/dev/tty"
        self.userid: bytes = b"root"
        self.login: bytes = b"root"

        # Directory information
        # Current working directory
        self.cwd: bytes = b"/root"
        self.root: bytes = b"/"

        # nice value
        self.nice: int = 10

        # sysconf values
        self.sysconf: typing.Dict[int, int] = {}

        # confstr values
        self.confstr: typing.Dict[int, bytes] = {}

        # Program break
        self.brk: int = 0

    @classmethod
    def get(cls) -> "ProcInfoManager":
        """Get an instance of this class

        NOTE: This isn't a true singleton, and I want it that way.
        Everything that asks for a manager during setup
        should get the same instance,
        but deep-copies of Machines should get their own managers

        Returns:
            An instance of the manager
        """
        if cls._singleton is None:
            cls._singleton = cls()
        return cls._singleton
