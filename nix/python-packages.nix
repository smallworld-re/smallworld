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
    in
    {
      unicorn = unicornPy.override { unicorn = patchedUnicorn; };
      unicornafl = mkUnicornafl pythonPkgs;
      # PANDA's Python bindings come from the dedicated packaging module in
      # `nix/panda-packages.nix`; they cannot be built directly from uv.lock.
      pypanda = pandaNgPackages.${system}.pypandaBuilder pythonPkgs;
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
      };
    in
    pyprojectPackages.overrideScope (
      lib.composeManyExtensions [
        pyproject-build-systems.overlays.wheel
        (workspace.mkPyprojectOverlay { sourcePreference = "wheel"; })
        (pkgs.callPackage ../overrides.nix { inherit python; })
        prebuiltOverlay
      ]
    );

  # Compute the locked package set once per platform so other modules can
  # reuse it instead of rebuilding the package graph for every output.
  pythonSets = forEachSystem (system: mkPythonSet { inherit system; });

  mkLockedVirtualenv =
    system: name: selection:
    pythonSets.${system}.mkVirtualEnv name (addPrebuiltPlaceholders selection);

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
    devSelection
    mkLockedVirtualenv
    mkPythonSet
    mkSmallworldPythonModule
    pythonSets
    runtimeSelection
    ;
}
