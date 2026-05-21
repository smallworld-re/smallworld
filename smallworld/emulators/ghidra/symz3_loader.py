"""Loader for Ghidra's SymbolicSummaryZ3 extension.

The extension ships with Ghidra 12.0.2+ as an *unextracted* zip under
``$GHIDRA_INSTALL_DIR/Extensions/Ghidra/ghidra_*_SymbolicSummaryZ3.zip``.
Pyghidra does not auto-extract it, so we extract once into the user's Ghidra
settings directory at ``~/.config/ghidra/ghidra_<ver>_<release>/Extensions/``
and rely on Ghidra's normal Application initialization to discover the
extension (classpath + native libraries + Sleigh-side registrations).

Must be called before any code that imports ``ghidra.pcode.emu.symz3``. Starts
pyghidra as a side effect if it has not already been started.
"""

from __future__ import annotations

import logging
import os
import pathlib
import platform as _py_platform
import zipfile

log = logging.getLogger(__name__)

_ALREADY_LOADED = False
_MIN_GHIDRA_VERSION = (12, 0, 2)


def _find_install_dir(install_dir: pathlib.Path | None) -> pathlib.Path:
    if install_dir is not None:
        return pathlib.Path(install_dir)
    env = os.environ.get("GHIDRA_INSTALL_DIR")
    if not env:
        raise RuntimeError(
            "GHIDRA_INSTALL_DIR is not set and no install_dir was provided. "
            "GhidraSymbolicEmulator requires a Ghidra installation that includes "
            "the SymbolicSummaryZ3 extension (Ghidra >= 12.0.2)."
        )
    return pathlib.Path(env)


def _application_properties(install_dir: pathlib.Path) -> dict[str, str]:
    props_path = install_dir / "Ghidra" / "application.properties"
    if not props_path.exists():
        return {}
    out: dict[str, str] = {}
    for line in props_path.read_text().splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            key, _, value = line.partition("=")
            out[key.strip()] = value.strip()
    return out


def _ghidra_version_tuple(props: dict[str, str]) -> tuple[int, int, int] | None:
    version = props.get("application.version")
    if not version:
        return None
    parts = version.split(".")
    try:
        return tuple(int(p) for p in parts[:3])  # type: ignore[return-value]
    except ValueError:
        return None


def _user_settings_dir(props: dict[str, str]) -> pathlib.Path:
    """Return Ghidra's per-user settings directory for this version+release.

    Must match the path Ghidra's own ``Application.getUserSettingsDir()``
    resolves to, since the Java side only scans that directory for installed
    extensions. Conventions (mirroring pyghidra's ``launcher._lastrun``):

      - ``XDG_CONFIG_HOME`` set      -> ``$XDG_CONFIG_HOME/ghidra/<name>``
      - macOS                        -> ``~/Library/ghidra/<name>``
      - Linux and other Unix-likes   -> ``~/.config/ghidra/<name>``
    """
    version = props.get("application.version", "")
    release = props.get("application.release.name", "")
    if not version:
        raise RuntimeError(
            "Could not read application.version from Ghidra's application.properties"
        )
    name = f"ghidra_{version}_{release}" if release else f"ghidra_{version}"

    xdg = os.environ.get("XDG_CONFIG_HOME")
    if xdg:
        base = pathlib.Path(xdg)
    elif _py_platform.system() == "Darwin":
        base = pathlib.Path.home() / "Library"
    else:
        base = pathlib.Path.home() / ".config"
    return base / "ghidra" / name


def _native_layout() -> tuple[str, str]:
    """Return ``(subdir_under_os, shared_lib_suffix)`` for the current platform.

    The SymbolicSummaryZ3 extension lays out per-platform native libs as
    ``os/<subdir>/libz3.<suffix>`` and ``os/<subdir>/libz3java.<suffix>``.
    """
    system = _py_platform.system()
    machine = _py_platform.machine().lower()
    if system == "Linux" and machine in ("x86_64", "amd64"):
        return "linux_x86_64", "so"
    if system == "Darwin" and machine in ("arm64", "aarch64"):
        return "mac_arm_64", "dylib"
    raise NotImplementedError(
        f"SymbolicSummaryZ3 native libraries are not bundled for "
        f"{system}/{machine} in this build of SmallWorld."
    )


def _find_extension_zip(install_dir: pathlib.Path) -> pathlib.Path:
    ext_dirs = [
        install_dir / "Extensions" / "Ghidra",
        install_dir / "Ghidra" / "Extensions" / "Ghidra",
    ]
    for ext_dir in ext_dirs:
        if not ext_dir.is_dir():
            continue
        matches = sorted(ext_dir.glob("*SymbolicSummaryZ3*.zip"))
        if matches:
            return matches[0]
    searched = ", ".join(str(p) for p in ext_dirs)
    raise RuntimeError(
        f"Could not find SymbolicSummaryZ3 extension under any of: {searched}. "
        f"GhidraSymbolicEmulator requires Ghidra >= 12.0.2 with the "
        f"SymbolicSummaryZ3 extension installed."
    )


def _install_extension(
    zip_path: pathlib.Path, user_ext_dir: pathlib.Path
) -> pathlib.Path:
    """Extract the SymbolicSummaryZ3 extension into the user extensions dir.

    Idempotent: a marker file inside the extracted directory short-circuits
    re-extraction once it has run successfully. The marker tracks the source
    zip's mtime so a newer Ghidra install triggers a fresh extract.
    """
    user_ext_dir.mkdir(parents=True, exist_ok=True)
    install_marker = user_ext_dir / "SymbolicSummaryZ3" / ".smallworld_installed"
    src_mtime = zip_path.stat().st_mtime_ns
    if install_marker.exists():
        try:
            if int(install_marker.read_text().strip()) == src_mtime:
                return user_ext_dir / "SymbolicSummaryZ3"
        except ValueError:
            pass

    log.info("Installing SymbolicSummaryZ3 from %s into %s", zip_path, user_ext_dir)
    with zipfile.ZipFile(zip_path) as z:
        z.extractall(user_ext_dir)
    install_marker.write_text(str(src_mtime))
    return user_ext_dir / "SymbolicSummaryZ3"


def ensure_loaded(install_dir: pathlib.Path | None = None) -> None:
    """Idempotently extract and load the SymbolicSummaryZ3 extension.

    Safe to call repeatedly. Starts pyghidra as a side effect if it has not
    been started; once started, the JVM is hot for the rest of the process.
    """
    global _ALREADY_LOADED
    if _ALREADY_LOADED:
        return

    install_dir = _find_install_dir(install_dir)
    props = _application_properties(install_dir)
    version = _ghidra_version_tuple(props)
    if version is not None and version < _MIN_GHIDRA_VERSION:
        raise RuntimeError(
            f"Ghidra {'.'.join(map(str, version))} is too old for "
            f"GhidraSymbolicEmulator (need >= "
            f"{'.'.join(map(str, _MIN_GHIDRA_VERSION))})."
        )

    zip_path = _find_extension_zip(install_dir)
    user_settings = _user_settings_dir(props)
    user_ext_dir = user_settings / "Extensions"
    ssz3_dir = _install_extension(zip_path, user_ext_dir)

    native_subdir, lib_suffix = _native_layout()
    native_dir = ssz3_dir / "os" / native_subdir
    libz3 = native_dir / f"libz3.{lib_suffix}"
    libz3java = native_dir / f"libz3java.{lib_suffix}"
    for required in (libz3, libz3java):
        if not required.exists():
            raise RuntimeError(
                f"SymbolicSummaryZ3 layout missing {required}; the extension "
                f"zip at {zip_path} may be corrupt."
            )

    # libz3java has a dynamic-loader reference to libz3 (DT_NEEDED on Linux,
    # LC_LOAD_DYLIB on macOS); the OS linker resolves it at the moment
    # System.load() runs. Pyghidra starts the JVM the first time it is
    # imported, so the search path must be set first.
    _prepend_dynamic_library_path(str(native_dir))

    import pyghidra

    if not pyghidra.started():
        pyghidra.start()

    # Ghidra's Application initialization discovers the extension (jars +
    # native libs) by scanning the user Extensions directory we just
    # populated. Confirm the SymZ3 classes are resolvable; if not, fail
    # loudly here rather than deeper inside the SymZ3 emulator constructor.
    import jpype  # noqa: F401

    jpype.JClass("com.microsoft.z3.Context")
    jpype.JClass("ghidra.pcode.emu.symz3.state.SymZ3PcodeEmulator")

    _ALREADY_LOADED = True


def _prepend_dynamic_library_path(path: str) -> None:
    env_var = (
        "DYLD_LIBRARY_PATH"
        if _py_platform.system() == "Darwin"
        else "LD_LIBRARY_PATH"
    )
    existing = os.environ.get(env_var, "")
    parts = [p for p in existing.split(":") if p]
    if path in parts:
        return
    os.environ[env_var] = path + (":" + existing if existing else "")
