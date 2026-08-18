# SmallWorld Nix Architecture

This directory holds the implementation behind the root `flake.nix`.
The top-level flake is meant to read like a map. The details live here.

## The Short Version

If you only remember one thing, remember this data flow:

1. `pyproject.toml` and `uv.lock` describe the Python world.
2. `nix/python-packages.nix` turns that lockfile into Nix Python packages.
3. `nix/runtime-support.nix` turns those packages into user-facing shells and runtime environments.
4. `nix/aflplusplus-packages.nix` provides the repo-local Darwin AFL++ build.
5. `nix/panda-packages.nix` handles the other unusual dependency, PANDA.
6. `nix/testfloat.nix` builds Berkeley TestFloat, the FPU conformance suite the `testfloat` scenario drives.
7. `nix/unicornafl-build/` keeps the repo-local `unicornafl` packaging helper next to the rest of the flake code.

## File Guide

- `python-packages.nix`
  Reads the Python workspace, builds the lockfile-backed Python package sets, and swaps in the few packages that need native compilation.
- `runtime-support.nix`
  Builds the environments people use: `nix develop`, `nix build`, and the downstream helper APIs `smallworld.lib.mkPython` and `smallworld.lib.mkPythonShell`.
- `aflplusplus-packages.nix`
  Builds the Darwin AFL++ command line tools that SmallWorld uses together with the separately packaged `unicornafl` Python binding.
- `unicornafl-build/`
  Holds the custom `unicornafl` derivation and its pinned Rust `Cargo.lock`, so the Python binding stays reproducible without leaving the `nix/` tree.
- `panda-packages.nix`
  Packages PANDA, QEMU, and `pypanda`. This file is special because PANDA needs generated headers and extra native build steps that do not fit the normal Python lockfile flow.
- `testfloat.nix`
  Builds Berkeley TestFloat and its SoftFloat reference from the upstream release zips. Nothing is vendored: `testfloat_gen` and `testfloat_ver` land on the developer shell's `PATH` at *test* time so the `testfloat` scenario can pipe emulated FPU results between them. It is deliberately outside `runtimeToolsFor`, so it stays out of `nix build` and the Docker image. Note that SoftFloat's `SPECIALIZE_TYPE` selects NaN-propagation semantics rather than a host architecture, which is why the harness leaves `testfloat_ver -checkNaNs` off.
- `patches/`
  Temporary local fixes for PANDA/libpanda, SuperH support in PANDA/QEMU, and the Styx Python bindings. These should go away once the equivalent changes exist upstream.

## User-Facing Commands

From the repo root:

```bash
nix develop
nix build
nix build .#smallworld-re
```

Those are the supported public entrypoints for the main flake.

For heavyweight artifact/test builds, use the separate CI flake:

```bash
nix build ./ci#tests
nix build ./ci#rtos_demo
```

## Why PANDA Is Separate

Most of SmallWorld can be explained as "Python packages from `uv.lock`, plus a few native tools on `PATH`."
PANDA breaks that pattern because:

- the Python package depends on native shared libraries
- those libraries depend on generated headers
- the header generation path still wants Linux build behavior, even when the host is macOS

That is why `panda-packages.nix` exists at all. If PANDA becomes easy to consume as an ordinary package, this directory should get noticeably smaller.
