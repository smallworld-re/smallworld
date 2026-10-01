"""The dependency sets the ABI tables may be generated from.

Stage 1 refuses any pypcode/angr/archinfo combination not listed here, so a
resolver that floats to a new release fails the build loudly instead of
silently changing the shipped tables. The overlay's Deviations are keyed by
these versions, and CI builds the tables under every set and asserts that
they are byte-identical.

Any listed set may build the tables on any Python that generates data;
which set a build gets is up to its environment. pyproject.toml's
build-isolation pins pick one per Python (below); nix uses its own lock
(nix/abi-build-tools); the dev environment uses the runtime lock's pypcode
and angr.

To add a set: pin it in ``[build-system] requires`` in pyproject.toml (and
in ``nix/abi-build-tools`` for nix), list it here with the digests of the
files stage 1 reads, build under it, and add the Deviations the build reports
until the tables match the other sets.
"""

import dataclasses
import hashlib
import typing


@dataclasses.dataclass(frozen=True)
class DependencySet:
    pypcode: str
    ghidra: str
    """The Ghidra release whose processor specs this pypcode bundles."""
    angr: str
    archinfo: str
    digests: typing.Mapping[str, str] = dataclasses.field(default_factory=dict)
    """SHA-256 of every file stage 1 takes facts from, keyed
    ``"<package>:<path>"`` (``ghidra:`` paths are relative to pypcode's
    processors directory, ``angr:`` and ``archinfo:`` paths to the
    package): per joined language its ``.ldefs``, compiler spec and
    compiled ``.sla`` (the SLEIGH register table); angr's
    ``calling_conventions.py`` and ``sim_type.py`` (the probes build types
    from it); archinfo's architecture module and ``tls.py``. Stage 1 refuses
    a file whose content differs, or that has no pin: a version number alone
    does not prove the facts are the ones the overlay was checked against
    (a patched or repackaged release, or a tampered install). The rest of
    pypcode, angr and archinfo (their native code, and modules these import)
    is covered by the version allow-list only."""


_X86_64_GHIDRA = {
    "ghidra:x86/data/languages/x86-64-gcc.cspec": (
        "5eaa848f3eba7ebd4023541f9f37645dae077e8426fb562592f398d599530a9e"
    ),
    "ghidra:x86/data/languages/x86.ldefs": (
        "b2aa14d94a6162844b18bf47f2aed8579bf90cef3459f6e322b9c1f58146098b"
    ),
}

# archinfo's TLSArchInfo is unchanged between the supported releases.
_ARCHINFO_TLS = {
    "archinfo:tls.py": (
        "df917290f010464941075e2b5f1d86d36f899d0e166969a15ce28cf01b67eab7"
    ),
}

#: Every supported set. The first is the reference set named in reports.
SUPPORTED: typing.Tuple[DependencySet, ...] = (
    DependencySet(
        pypcode="4.0.0",
        ghidra="12.1",
        angr="10.0.0",
        archinfo="10.0.0",
        digests={
            **_X86_64_GHIDRA,
            **_ARCHINFO_TLS,
            "ghidra:x86/data/languages/x86-64.sla": (
                "d5adc314e2278228b380d8f653b2b579fa4a65986bb1d39b095e461fd5432481"
            ),
            "angr:sim_type.py": (
                "203d795dc8abff40815e7b1dc01b573fd6e5b251a328fbe945f89953328a8bcd"
            ),
            "angr:calling_conventions.py": (
                "22a50f83954351b1001d9288ee6e3a04ab4250eaaf1e39bbb66de5909dce9262"
            ),
            "archinfo:arch_amd64.py": (
                "1fd4864629f2b66a401168de6805d0f75db4a7349460215fce8c32e987e76a38"
            ),
        },
    ),
    DependencySet(
        pypcode="3.3.3",
        ghidra="11.4.2",
        angr="9.2.194",
        archinfo="9.2.194",
        digests={
            **_X86_64_GHIDRA,
            **_ARCHINFO_TLS,
            "ghidra:x86/data/languages/x86-64.sla": (
                "4d3ebe1ebf0b127dc5bd187979824b850fc94081e6660021e2bda834e7400504"
            ),
            "angr:sim_type.py": (
                "d42acd991a6d4987b9bec2e885d028d2a2961056bcd3da6a12c4f809d28a6e79"
            ),
            "angr:calling_conventions.py": (
                "5c24685170da003c7d8eed6003cd2b0a3d276abee0d1329d003e1094e2e048e6"
            ),
            "archinfo:arch_amd64.py": (
                "cabba40c092efd022b36dea1eb58946331736c76c5f9101f374ac785f6b63311"
            ),
        },
    ),
)


class PinnedFiles:
    """Checks file contents against a dependency set's pinned digests,
    collecting every mismatch."""

    def __init__(self, dependency_set: DependencySet) -> None:
        self.set = dependency_set
        self.problems: typing.List[str] = []

    def check(self, key: str, data: bytes) -> bool:
        """Whether `data` is the pinned content of `key`; records why not."""
        digest = hashlib.sha256(data).hexdigest()
        pinned = self.set.digests.get(key)
        name = (
            f"pypcode {self.set.pypcode} / angr {self.set.angr} / "
            f"archinfo {self.set.archinfo}"
        )
        if pinned is None:
            self.problems.append(
                f"{key} (SHA-256 {digest}) has no pinned digest for {name}; add it "
                "to tools/abi/overlay/versions.py once the tables built from it "
                "have been checked"
            )
        elif pinned != digest:
            self.problems.append(
                f"{key} has SHA-256 {digest}, but tools/abi/overlay/versions.py "
                f"pins {pinned} for {name}: the installed file is not the one the "
                "overlay was checked against (a patched or repackaged release, or "
                "a modified install). Reinstall the pinned release, or re-verify "
                "the tables under it and update the pin."
            )
        return pinned == digest


#: The Python versions whose builds generate data, and the set that
#: pyproject.toml's build-isolation pins install for them (a build may use
#: any listed set; they all give the same tables). Builds on any other Python
#: (3.9, 3.11) write the no-data marker: no angr release installs on 3.11
#: alongside a supported pypcode, and 3.9 has neither.
PINNED_FOR_PYTHON: typing.Tuple[typing.Tuple[typing.Tuple[int, int], str], ...] = (
    ((3, 10), "3.3.3"),
    ((3, 12), "4.0.0"),
)


def pinned_set(version_info: typing.Sequence[int]) -> typing.Optional[DependencySet]:
    """The dependency set a build on this Python uses, or ``None`` if a build
    on this Python generates no data."""
    major_minor = (version_info[0], version_info[1])
    pypcode = None
    for python, pinned in PINNED_FOR_PYTHON:
        if major_minor == python or (python == (3, 12) and major_minor > python):
            pypcode = pinned
    for dependency_set in SUPPORTED:
        if dependency_set.pypcode == pypcode:
            return dependency_set
    return None


def no_data_reason(version_info: typing.Sequence[int]) -> typing.Optional[str]:
    """Why a build on this Python ships no ABI data (``None`` if it does)."""
    if pinned_set(version_info) is not None:
        return None
    return (
        f"smallworld was built on Python {version_info[0]}.{version_info[1]}, and "
        "the ABI tables are generated at build time only on Python 3.10 and on "
        "Python 3.12 or later, the interpreters with a supported pypcode and angr "
        "(build smallworld on one of those to get them; a wheel built there works "
        "on any supported Python)"
    )


def find(pypcode: str, angr: str, archinfo: str) -> DependencySet:
    """The supported set for these versions. Raises ValueError otherwise."""
    for dependency_set in SUPPORTED:
        if (dependency_set.pypcode, dependency_set.angr, dependency_set.archinfo) == (
            pypcode,
            angr,
            archinfo,
        ):
            return dependency_set
    supported = "; ".join(
        f"pypcode {s.pypcode} + angr {s.angr} + archinfo {s.archinfo}"
        for s in SUPPORTED
    )
    raise ValueError(
        f"pypcode {pypcode} + angr {angr} + archinfo {archinfo} is not a supported "
        f"dependency set for generating smallworld's ABI tables (supported: "
        f"{supported}). Install a supported set, or add this one to "
        "tools/abi/overlay/versions.py and pyproject.toml's [build-system] requires "
        "after building under it and adding the Deviations it needs (see that "
        "file's docstring)."
    )
