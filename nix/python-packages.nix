# Python package construction for the main SmallWorld flake.
#
# This module does the "lockfile to Python package set" work:
# 1. read `pyproject.toml` and `uv.lock`
# 2. ask uv2nix/pyproject.nix to produce a Python package graph
# 3. replace the few packages that need native compilation outside the lockfile
# 4. expose helpers that other modules can use to build envs and shells
#
# If you are new to Nix, this file is the answer to:
# "How do we turn the Python dependency lockfile into installable packages?"
{
  lib,
  forEachSystem,
  pkgsFor,
  pythonFor,
  pyproject-nix,
  pyproject-build-systems,
  uv2nix,
  pandaNgPackages,
}:

let
  # Only copy the files that affect the Python dependency graph. This keeps
  # unrelated source edits from forcing uv2nix to rebuild everything.
  workspaceRoot =
    let
      fileset = lib.fileset.unions [
        ../pyproject.toml
        ../uv.lock
        ../.python-version
        ../smallworld
        # the build-time ABI generator run by the build_py hook (pyproject.toml)
        ../tools/abi
        # license-files in pyproject.toml, so the wheel ships the MIT text
        ../LICENSE.txt
      ];
    in
    /.
    + builtins.unsafeDiscardStringContext (
      lib.fileset.toSource {
        inherit fileset;
        root = ../.;
      }
    );

  workspace = uv2nix.lib.workspace.loadWorkspace { inherit workspaceRoot; };

  selectWorkspaceDeps =
    extras:
    workspace.deps.default
    // {
      smallworld-re = extras;
    };

  # The published runtime wants every emulator backend. The dev shell layers
  # the project's developer dependency group on top of that same runtime set.
  runtimeSelection = selectWorkspaceDeps [ "emu-all" ];
  devSelection = selectWorkspaceDeps ([ "emu-all" ] ++ workspace.deps.groups.smallworld-re);

  # These packages are built locally in Nix instead of coming directly from
  # the Python lockfile. We give uv2nix empty placeholders so it knows not to
  # also fetch them from PyPI.
  prebuiltPythonPackages = [
    "unicornafl"
    "pypanda"
    "unicorn"
    "styx-emulator"
    "styxafl"
    "triton-library"
  ];

  addPrebuiltPlaceholders = deps: deps // lib.genAttrs prebuiltPythonPackages (_: [ ]);

  # A small number of Python packages need native compilation or custom source
  # handling. Everything else still comes from the lockfile-generated package
  # set below.
  mkNativePythonAddons =
    {
      system,
      pythonPkgs,
      unicornPy,
      pkgs ? pkgsFor system,
    }:
    let
      patchedUnicornSrc = pkgs.fetchFromGitHub {
        owner = "appleflyerv3";
        repo = "unicorn";
        rev = "mmio_map_pc_sync";
        hash = "sha256-0MH+JS/mPESnTf21EOfGbuVrrrxf1i8WzzwzaPeCt1w=";
      };
      patchedUnicorn = pkgs.unicorn.overrideAttrs (_: {
        src = patchedUnicornSrc;
      });
      mkUnicornafl = pkgs.callPackage ./unicornafl-build {
        unicornLibraryPath = "${patchedUnicorn}/lib";
      };
      mkStyxEmulator = pkgs.callPackage ./styx-emulator-build { };
      mkStyxafl = pkgs.callPackage ./styxafl-build { };
      mkTriton = pkgs.callPackage ./triton-build { };
    in
    {
      unicorn = unicornPy.override { unicorn = patchedUnicorn; };
      unicornafl = mkUnicornafl pythonPkgs;
      # PANDA's Python bindings come from the dedicated packaging module in
      # `nix/panda-packages.nix`; they cannot be built directly from uv.lock.
      pypanda = pandaNgPackages.${system}.pypandaBuilder pythonPkgs;
      # Styx bindings are built from the upstream source via maturin; the
      # `styxafl` bridge crate lives under `nix/styxafl-src/` and depends on
      # the same pinned styx-emulator revision.
      styx-emulator = mkStyxEmulator pythonPkgs;
      styxafl = mkStyxafl pythonPkgs;
      # Triton's CPython bindings are compiled from a pinned upstream revision
      # via CMake (see `nix/triton-build/`); the PyPI wheel predates RISC-V.
      "triton-library" = mkTriton pythonPkgs;
    };

  # Build one locked Python package set for one platform/interpreter pair.
  #
  # Order matters:
  # 1. start from uv/pyproject metadata
  # 2. add standard build backends
  # 3. apply local package fixes from `overrides.nix`
  # 4. replace a few packages with the native builds above
  mkPythonSet =
    {
      system,
      pkgs ? pkgsFor system,
      python ? pythonFor system,
      # false: build smallworld-re without ABI tables (the dev shell's copy,
      # which the live checkout shadows; see abiBuildToolsOverlay).
      abiTables ? true,
    }:
    let
      pyprojectPackages = pkgs.callPackage pyproject-nix.build.packages { inherit python; };
      pyprojectHacks = pkgs.callPackage pyproject-nix.build.hacks { };

      nativeAddons = mkNativePythonAddons {
        inherit system pkgs;
        pythonPkgs = python.pkgs;
        unicornPy = python.pkgs.unicorn;
      };

      prebuiltOverlay = _final: _prev: {
        unicorn = pyprojectHacks.nixpkgsPrebuilt { from = nativeAddons.unicorn; };
        unicornafl = pyprojectHacks.nixpkgsPrebuilt { from = nativeAddons.unicornafl; };
        pypanda = pyprojectHacks.nixpkgsPrebuilt { from = nativeAddons.pypanda; };
        styx-emulator = pyprojectHacks.nixpkgsPrebuilt { from = nativeAddons.styx-emulator; };
        styxafl = pyprojectHacks.nixpkgsPrebuilt { from = nativeAddons.styxafl; };
        "triton-library" = pyprojectHacks.nixpkgsPrebuilt {
          from = nativeAddons."triton-library";
        };
      };
    in
    pyprojectPackages.overrideScope (
      lib.composeManyExtensions [
        pyproject-build-systems.overlays.wheel
        (workspace.mkPyprojectOverlay { sourcePreference = "wheel"; })
        (pkgs.callPackage ../overrides.nix { inherit python; })
        prebuiltOverlay
        (abiBuildToolsOverlay system abiTables)
      ]
    );

  # The build tools the ABI generator dumps its tables from (stage 1 of
  # tools/abi). uv2nix resolves smallworld-re's [build-system] requires by
  # name from the runtime lock, which pins pypcode 3.3.3 and angr 9.2.194,
  # ignoring the build-isolation pins. Those would also give identical tables
  # (every allow-listed set does), but they are the pins of the 3.10 build;
  # the pypcode 4.0.0 + angr 10.0.0 set pinned for 3.12 gets its own lock
  # (nix/abi-build-tools) and environment, always on the flake's Python.
  abiToolsWorkspace = uv2nix.lib.workspace.loadWorkspace {
    workspaceRoot =
      /.
      + builtins.unsafeDiscardStringContext (
        lib.fileset.toSource {
          root = ./abi-build-tools;
          fileset = lib.fileset.unions [
            ./abi-build-tools/pyproject.toml
            ./abi-build-tools/uv.lock
          ];
        }
      );
  };

  mkAbiBuildTools =
    {
      system,
      pkgs ? pkgsFor system,
      python ? pythonFor system,
    }:
    let
      pyprojectPackages = pkgs.callPackage pyproject-nix.build.packages { inherit python; };
      toolsSet = pyprojectPackages.overrideScope (
        lib.composeManyExtensions [
          pyproject-build-systems.overlays.wheel
          (abiToolsWorkspace.mkPyprojectOverlay { sourcePreference = "wheel"; })
          (pkgs.callPackage ../overrides.nix { inherit python; })
          # On Linux, angr 10 links against its own pyvex (not nixpkgs') and,
          # through its Rust extension, the z3 library the z3-solver wheel
          # ships. uv2nix adds autoPatchelfHook only on Linux, so the patching
          # is Linux-only; darwin builds try the wheels as they are.
          (
            final: prev:
            lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux {
              angr = prev.angr.overrideAttrs (old: {
                autoPatchelfLibs = [ "${final.pyvex}/${python.sitePackages}/pyvex/lib" ];
                preFixup = (old.preFixup or "") + ''
                  addAutoPatchelfSearchPath ${final.z3-solver}/${python.sitePackages}/z3/lib
                '';
              });
            }
          )
        ]
      );
    in
    toolsSet.mkVirtualEnv "smallworld-abi-build-tools" abiToolsWorkspace.deps.default;

  abiBuildTools = forEachSystem (system: mkAbiBuildTools { inherit system; });

  # Run the ABI generator's stage 1 under the build tools above; or, for the
  # dev shell's copy of smallworld-re, generate no tables at all, so that a
  # broken overlay in the checkout can never stop `nix develop` (the shell's
  # hook regenerates the tables in-tree, and warns if it cannot).
  abiBuildToolsOverlay =
    system: abiTables: _final: prev:
    lib.optionalAttrs (prev ? smallworld-re) {
      smallworld-re = prev.smallworld-re.overrideAttrs (
        _:
        if abiTables then
          { SMALLWORLD_ABI_STAGE1_PYTHON = "${abiBuildTools.${system}}/bin/python"; }
        else
          { SMALLWORLD_ABI_ALLOW_MISSING = "1"; }
      );
    };

  # Compute the locked package set once per platform so other modules can
  # reuse it instead of rebuilding the package graph for every output.
  pythonSets = forEachSystem (system: mkPythonSet { inherit system; });
  devPythonSets = forEachSystem (
    system:
    mkPythonSet {
      inherit system;
      abiTables = false;
    }
  );

  mkLockedVirtualenv =
    system: name: selection:
    pythonSets.${system}.mkVirtualEnv name (addPrebuiltPlaceholders selection);

  # The dev shell's environment: its smallworld-re carries no ABI tables.
  mkDevVirtualenv =
    system: name: selection:
    devPythonSets.${system}.mkVirtualEnv name (addPrebuiltPlaceholders selection);

  resolveLockedDependencyNames =
    pythonSet: name: enabledExtras:
    let
      rawPackage = pythonSet.${name};
      selectedDeps = lib.zipAttrsWith (_depName: extrasLists: lib.unique (lib.flatten extrasLists)) (
        [ (rawPackage.dependencies or { }) ]
        ++ map (extra: rawPackage.optional-dependencies.${extra} or { }) enabledExtras
      );
      dependencyNames = builtins.attrNames selectedDeps;
    in
    lib.unique (
      dependencyNames
      ++ lib.flatten (
        map (
          dependencyName: resolveLockedDependencyNames pythonSet dependencyName selectedDeps.${dependencyName}
        ) dependencyNames
      )
    );

  # Downstream callers want `python.withPackages (ps: [ ps.smallworld ])` to
  # behave like a normal nixpkgs Python package set. To make that work we turn
  # the locked SmallWorld wheel into a proper Python module and explicitly add
  # the full transitive dependency closure that `python.withPackages` expects.
  mkSmallworldPythonModule =
    {
      pythonSet,
      py-final,
      smallworldExtras,
    }:
    let
      rawSmallworld = pythonSet.smallworld-re;

      pypandaModule = if pythonSet ? pypanda then py-final.toPythonModule pythonSet.pypanda else null;

      dependencyNames = resolveLockedDependencyNames pythonSet "smallworld-re" smallworldExtras;

      dependencyModules =
        map (name: py-final.toPythonModule pythonSet.${name}) dependencyNames
        ++ lib.optional (builtins.elem "emu-panda" smallworldExtras && pypandaModule != null) pypandaModule;
    in
    py-final.toPythonModule (
      rawSmallworld.overrideAttrs (old: {
        propagatedBuildInputs = (old.propagatedBuildInputs or [ ]) ++ dependencyModules;
      })
    );
in
{
  inherit
    abiBuildTools
    devSelection
    mkDevVirtualenv
    mkLockedVirtualenv
    mkPythonSet
    mkSmallworldPythonModule
    pythonSets
    runtimeSelection
    ;
}
