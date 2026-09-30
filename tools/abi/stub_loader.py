"""Load smallworld's platform and ABI-schema modules from a source tree
without importing smallworld.

``smallworld/__init__.py`` imports the emulators, angr, claripy and more, so
stage 2 mounts the source package under a private top-level name instead and
loads only ``utils``, ``exceptions`` and ``platforms`` (with ``naming`` and
``abi``) from it. An import blocker turns any attempt to reach smallworld
itself or a heavy dependency into an immediate error, so stage 2 provably
depends on nothing but the standard library, capstone and those modules.
"""

import importlib
import importlib.abc
import importlib.util
import os
import sys
import types
import typing

#: The private name the source package is mounted under.
STUB = "_smallworld_src"

#: The stub package's data module.
DATA = f"{STUB}.platforms.abi._data"

#: Top-level modules stage 2 must never import.
BLOCKED = (
    "smallworld",
    "angr",
    "archinfo",
    "pypcode",
    "claripy",
    "pyvex",
    "cle",
    "lief",
    "unicorn",
    "pyghidra",
    "triton",
    "pandare2",
    "styx_emulator",
)

#: The source modules stage 2 may load (and their submodules).
ALLOWED = ("utils", "exceptions", "platforms")


class ImportBlocker(importlib.abc.MetaPathFinder):
    """A meta path finder that refuses every :data:`BLOCKED` module."""

    def find_spec(
        self,
        fullname: str,
        path: typing.Optional[typing.Sequence[str]] = None,
        target: typing.Optional[types.ModuleType] = None,
    ) -> None:
        if fullname.split(".", 1)[0] in BLOCKED:
            raise ImportError(
                f"ABI generator stage 2 must not import {fullname!r}: it may use "
                "only the standard library, capstone and smallworld's utils, "
                "exceptions and platforms modules, loaded from the source tree"
            )
        return None


def blocked_modules() -> typing.List[str]:
    return sorted(m for m in sys.modules if m.split(".", 1)[0] in BLOCKED)


def install_blocker() -> None:
    """Refuse every blocked import from now on in this process."""
    already = blocked_modules()
    if already:
        raise RuntimeError(f"imported before stage 2 started: {already}")
    if not any(isinstance(f, ImportBlocker) for f in sys.meta_path):
        sys.meta_path.insert(0, ImportBlocker())


class Smallworld(typing.NamedTuple):
    """The smallworld modules stage 2 works with."""

    platforms: types.ModuleType
    naming: types.ModuleType
    abi: types.ModuleType
    model: types.ModuleType
    enums: types.ModuleType
    validate: types.ModuleType


def from_modules(package: str) -> Smallworld:
    """The stage-2 modules of an already importable package (`package` is
    ``smallworld`` in tests, :data:`STUB` in stage 2)."""

    def load(name: str) -> types.ModuleType:
        return importlib.import_module(f"{package}.{name}")

    return Smallworld(
        platforms=load("platforms"),
        naming=load("platforms.naming"),
        abi=load("platforms.abi"),
        model=load("platforms.abi.model"),
        enums=load("platforms.abi.enums"),
        validate=load("platforms.abi.validate"),
    )


def load(src_root: str) -> Smallworld:
    """Mount ``<src_root>/smallworld`` as :data:`STUB` and load its stage-2
    modules. Fails if loading them pulls in anything outside
    :data:`ALLOWED`."""
    already = blocked_modules()
    if already:
        raise RuntimeError(
            f"already imported before stage 2: {already}; stage 2 must run in "
            "an interpreter that has not imported smallworld or its heavy "
            "dependencies"
        )
    _mount_stub(src_root)
    # smallworld.platforms.abi imports its data module as soon as it is
    # imported (the stub's registry derives the name, so it is the stub's
    # own). Stage 2 must not load whatever tables the source tree holds (an
    # earlier build's, perhaps stale or half written), so block it first: the
    # registry then records "no tables" and stage 2 builds its own. Tables
    # mounted with mount_data_package before load() are kept.
    sys.modules.setdefault(DATA, None)  # type: ignore[arg-type]
    loaded = from_modules(STUB)
    stray = [
        m
        for m in sorted(sys.modules)
        if m.startswith(STUB + ".")
        and m[len(STUB) + 1 :].split(".", 1)[0] not in ALLOWED
    ]
    stray += blocked_modules()  # loading the stub must not pull them in either
    if stray:
        raise RuntimeError(f"loading smallworld's platforms pulled in {stray}")
    return loaded


def _mount_stub(src_root: str) -> None:
    """Make ``<src_root>/smallworld`` importable as :data:`STUB`."""
    package_dir = os.path.join(os.path.abspath(src_root), "smallworld")
    if not os.path.isfile(os.path.join(package_dir, "platforms", "__init__.py")):
        raise FileNotFoundError(f"no smallworld/platforms package under {src_root}")
    if STUB not in sys.modules:
        package = types.ModuleType(STUB)
        package.__path__ = [package_dir]
        package.__package__ = STUB
        sys.modules[STUB] = package


def mount_data_package(
    sw_package: str,
    directory: str,
    submodule: str = "_data",
    src_root: typing.Optional[str] = None,
) -> types.ModuleType:
    """Import the generated package in `directory` as
    ``<sw_package>.platforms.abi.<submodule>``, so its relative imports resolve
    against `sw_package`. For :data:`STUB` before :func:`load`, pass
    `src_root` to mount the stub package first."""
    if sw_package == STUB and STUB not in sys.modules:
        if src_root is None:
            raise ValueError(f"mounting {STUB} tables before load() needs src_root")
        _mount_stub(src_root)
    name = f"{sw_package}.platforms.abi.{submodule}"
    # Forget any earlier module of that name (or the block load() installs),
    # and its submodules, so the directory's own files are imported.
    for loaded in [m for m in sys.modules if m == name or m.startswith(name + ".")]:
        del sys.modules[loaded]
    spec = importlib.util.spec_from_file_location(
        name,
        os.path.join(directory, "__init__.py"),
        submodule_search_locations=[directory],
    )
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {directory}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    registry = sys.modules.get(f"{sw_package}.platforms.abi.registry")
    if submodule == "_data" and registry is not None:
        # The registry loaded its tables when it was imported; serve these.
        registry._reload(name)
    return module
