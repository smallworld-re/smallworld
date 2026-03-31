# Nix flake for smallworld-re.
#
# This file has one job: turn the Python project described by
#   - pyproject.toml
#   - uv.lock
# into:
#   - a ready-to-use package (`nix build`)
#   - a development shell (`nix develop`)
#
# CI-only outputs such as test artifacts live in `./ci/flake.nix` so this
# top-level flake stays focused on the user-facing package and dev environment.
#
# A few Python dependencies (unicorn, unicornafl, pypanda) need native C/C++
# builds, so we build those ourselves and then insert them into the locked
# package graph from `uv.lock`.
{
  description = "smallworld-re";

  # ==========================================================================
  # Inputs — external dependencies fetched and pinned by nix.
  # "follows" means "reuse the same copy as the parent" to avoid duplicates.
  # ==========================================================================
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixpkgs-unstable";

    # uv2nix reads pyproject.toml + uv.lock and turns them into nix packages.
    # pyproject-nix provides the low-level build helpers it relies on.
    # pyproject-build-systems provides standard Python build backends (setuptools, etc.).
    pyproject-nix = {
      url = "github:pyproject-nix/pyproject.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    uv2nix = {
      url = "github:pyproject-nix/uv2nix";
      inputs.pyproject-nix.follows = "pyproject-nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    pyproject-build-systems = {
      url = "github:pyproject-nix/build-system-pkgs";
      inputs.pyproject-nix.follows = "pyproject-nix";
      inputs.uv2nix.follows = "uv2nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    # PANDA-ng: a dynamic analysis / whole-system emulation platform.
    # Provides the pypanda Python bindings.
    panda-ng = {
      url = "github:panda-re/panda-ng";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    # Optional Binary Ninja support (uncomment both to enable).
    #  binaryninja = {
    #    url = "github:jchv/nix-binary-ninja";
    #    inputs.nixpkgs.follows = "nixpkgs";
    #  };
    #  binjaZip = {
    #    url = "path:./binaryninja_linux_stable_ultimate.zip";
    #    flake = false;
    #  };

  };

  # ==========================================================================
  # Outputs — what this flake provides.
  # ==========================================================================
  outputs =
    inputs@{
      nixpkgs,
      pyproject-nix,
      uv2nix,
      pyproject-build-systems,
      panda-ng,
      ...
    }:
    let
      lib = nixpkgs.lib;

      # Nix flakes usually build for more than one CPU/OS combination. This
      # helper lets us define one output and have it expanded for every system.
      systems = lib.systems.flakeExposed;
      forAllSystems = lib.genAttrs systems;

      # Short-hand for "give me nixpkgs for this system".
      pkgsFor = system: nixpkgs.legacyPackages.${system};

      # Optional Binary Ninja inputs (null when commented out above).
      binaryninja = inputs.binaryninja or null;
      binjaZip = inputs.binjaZip or null;

      # Ghidra installs into a larger directory tree; this is the path the
      # Python bindings expect.
      ghidraInstallDir = ghidra: "${ghidra}/lib/ghidra";

      # =====================================================================
      # Python workspace — reads pyproject.toml + uv.lock via uv2nix.
      # All Python dependency information lives in those files, not here.
      # =====================================================================

      # Only copy the files the Python build actually depends on. This keeps
      # unrelated repo changes from forcing a full Python rebuild.
      workspaceRoot =
        let
          fileset = lib.fileset.unions [
            ./pyproject.toml
            ./uv.lock
            ./.python-version
            ./smallworld
          ];
        in
        /.
        + builtins.unsafeDiscardStringContext (
          lib.fileset.toSource {
            inherit fileset;
            root = ./.;
          }
        );

      # Load the workspace. This parses pyproject.toml and uv.lock.
      workspace = uv2nix.lib.workspace.loadWorkspace { inherit workspaceRoot; };

      # The published package wants all emulator backends, but not the repo's
      # development-only tools. The dev shell adds the `dev` group on top.
      runtimeExtras = [ "emu-all" ];
      devGroups = workspace.deps.groups.smallworld-re;

      # uv2nix expects an attribute set of:
      #   { <workspace-package-name> = [ enabled-extra-or-group names... ]; }
      # These two selections drive the runtime package and the dev shell.
      runtimeDeps = workspace.deps.default // {
        smallworld-re = runtimeExtras;
      };
      devDeps = workspace.deps.default // {
        smallworld-re = runtimeExtras ++ devGroups;
      };

      # For the packages we build ourselves below, give uv2nix an empty
      # placeholder so it does not also try to fetch them from PyPI.
      prebuiltNames = [
        "unicornafl"
        "pypanda"
        "unicorn"
      ];
      addPrebuiltPlaceholders = deps: deps // lib.genAttrs prebuiltNames (_: [ ]);

      # =====================================================================
      # Native Python packages — these need C/C++ compilation and cannot come
      # straight from wheels. We build them from source and inject them into
      # the uv2nix package set.
      # =====================================================================

      basePython = forAllSystems (system: (pkgsFor system).python312);

      # Build the Python packages we cannot safely consume as wheels.
      #
      # Returned as a function so we can plug the same logic into different
      # Python package sets later.
      pythonNativeAddons = forAllSystems (
        system:
        { pythonPkgs, unicornPy }:
        {
          fetchFromGitHub,
          unicorn,
          callPackage,
          ...
        }:
        let
          mkUnicornafl = callPackage ./unicornafl-build { };
          patchedUnicornSrc = fetchFromGitHub {
            owner = "appleflyerv3";
            repo = "unicorn";
            rev = "mmio_map_pc_sync";
            hash = "sha256-0MH+JS/mPESnTf21EOfGbuVrrrxf1i8WzzwzaPeCt1w=";
          };
          patchedUnicorn = unicorn.overrideAttrs (_: {
            src = patchedUnicornSrc;
          });
          patchedUnicornPy = unicornPy.override { unicorn = patchedUnicorn; };
        in
        {
          unicorn = patchedUnicornPy;
          unicornafl = mkUnicornafl pythonPkgs;
          pypanda = panda-ng.lib.${system}.pypandaBuilder pythonPkgs;
        }
      );

      # Build the final locked Python package set for a given nixpkgs
      # instance and interpreter:
      #   1. standard Python build tools
      #   2. packages from uv.lock
      #   3. local fixes from overrides.nix
      #   4. the native packages we build ourselves
      #
      # Keeping this as a reusable function lets downstream helpers build the
      # same package set against their own `pkgs`/`python` values without
      # needing a top-level nixpkgs overlay.
      mkPythonSet =
        {
          system,
          pkgs ? pkgsFor system,
          python ? pkgs.python312,
        }:
        let
          pyprojectPkgs = pkgs.callPackage pyproject-nix.build.packages { inherit python; };
          hacks = pkgs.callPackage pyproject-nix.build.hacks { };
          native = pythonNativeAddons.${system} {
            pythonPkgs = python.pkgs;
            unicornPy = python.pkgs.unicorn;
          } pkgs;

          nativePrebuilts = _final: _prev: {
            unicorn = hacks.nixpkgsPrebuilt { from = native.unicorn; };
            unicornafl = hacks.nixpkgsPrebuilt { from = native.unicornafl; };
            pypanda = hacks.nixpkgsPrebuilt { from = native.pypanda; };
          };
        in
        pyprojectPkgs.overrideScope (
          lib.composeManyExtensions [
            pyproject-build-systems.overlays.wheel
            (workspace.mkPyprojectOverlay { sourcePreference = "wheel"; })
            (pkgs.callPackage ./overrides.nix { inherit python; })
            nativePrebuilts
          ]
        );

      # Precompute the locked package set for each supported system. The rest
      # of this flake reuses these cached package sets for its own outputs.
      pythonSets = forAllSystems (system: mkPythonSet { inherit system; });

      # =====================================================================
      # Non-Python tools smallworld expects to find on PATH.
      # =====================================================================

      toolDeps = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
        in
        # aflplusplus is not packaged for Apple Silicon macOS, so keep it out
        # of that environment instead of making `nix develop` fail there.
        lib.optional (system != "aarch64-darwin") pkgs.aflplusplus
        ++ [
          pkgs.z3
          pkgs.ghidra
          pkgs.jdk
        ]
      );

      # Build a Python virtualenv directly from the locked package set.
      # This is the "Python only" environment before we add non-Python tools.
      mkLockedVirtualenv =
        system: name: selectedDeps:
        pythonSets.${system}.mkVirtualEnv name (addPrebuiltPlaceholders selectedDeps);

      # Compose multiple environments into one and preserve their setup hooks.
      # `extraSetupHook` lets us append a few exported variables afterwards.
      mkBuildEnvWithHook =
        {
          pkgs,
          name,
          paths,
          setupHookInputs ? [ ],
          extraSetupHook ? "",
        }:
        pkgs.buildEnv {
          inherit name paths;
          pathsToLink = [
            "/bin"
            "/nix-support"
          ];
          ignoreCollisions = true;

          postBuild = ''
            if [ -L "$out/nix-support" ]; then rm -f "$out/nix-support"; fi
            mkdir -p "$out/nix-support"
            if [ -e "$out/nix-support/setup-hook" ]; then rm -f "$out/nix-support/setup-hook"; fi
            : > "$out/nix-support/setup-hook"
          ''
          + lib.concatMapStrings (hookInput: ''
            if [ -f "${hookInput}/nix-support/setup-hook" ]; then
              cat "${hookInput}/nix-support/setup-hook" >> "$out/nix-support/setup-hook"
            fi
          '') setupHookInputs
          + lib.optionalString (extraSetupHook != "") ''
            cat >> "$out/nix-support/setup-hook" <<'EOF'
            ${extraSetupHook}
            EOF
          '';
        };

      # Build the runtime environment we want downstream users to consume:
      # the locked Python virtualenv plus the native tools smallworld needs.
      mkSmallworldEnv =
        {
          system,
          env,
          name ? "${env.name}-smallworld-full",
        }:
        let
          pkgs = pkgsFor system;
        in
        mkBuildEnvWithHook {
          inherit pkgs name;
          paths = [ env ] ++ toolDeps.${system};
          setupHookInputs = [ env ];
          extraSetupHook = ''
            export GHIDRA_INSTALL_DIR=${ghidraInstallDir pkgs.ghidra}
            export JAVA_HOME=${pkgs.jdk}
          '';
        };

      # Build the downstream-facing runtime environment. Downstream users can
      # optionally layer extra nixpkgs Python packages on top without needing
      # access to SmallWorld's internal package set.
      mkDownstreamEnv =
        {
          system,
          name ? "smallworld-re-env",
          extraPythonPackages ? (_: [ ]),
          extraPackages ? [ ],
        }:
        let
          pkgs = pkgsFor system;
          python = basePython.${system};
          basePythonEnv = mkLockedVirtualenv system "${name}-python" runtimeDeps;
          extraPython = extraPythonPackages python.pkgs;
          extraPythonEnv = if extraPython == [ ] then null else python.withPackages (_: extraPython);

          pythonEnv =
            if extraPythonEnv == null then
              basePythonEnv
            else
              mkBuildEnvWithHook {
                inherit pkgs;
                name = "${name}-python";
                paths = [
                  basePythonEnv
                  extraPythonEnv
                ];
                setupHookInputs = [ basePythonEnv ];
                extraSetupHook = ''
                  export PYTHONPATH=${extraPythonEnv}/${python.sitePackages}''${PYTHONPATH:+:$PYTHONPATH}
                '';
              };

          smallworldEnv = mkSmallworldEnv {
            inherit system;
            env = pythonEnv;
            inherit name;
          };
        in
        if extraPackages == [ ] then
          smallworldEnv
        else
          mkBuildEnvWithHook {
            inherit pkgs name;
            paths = [ smallworldEnv ] ++ extraPackages;
            setupHookInputs = [ smallworldEnv ];
          };

      # Build a ready-to-use shell for downstream consumers. This wraps the
      # assembled runtime environment so downstream flakes do not need to
      # write their own `pkgs.mkShell` boilerplate just to add a few extras.
      mkDownstreamShell =
        {
          system,
          name ? "smallworld-shell",
          extraPythonPackages ? (_: [ ]),
          extraPackages ? [ ],
          packages ? [ ],
          env ? { },
          shellHook ? "",
        }:
        let
          pkgs = pkgsFor system;
          smallworldEnv = mkDownstreamEnv {
            inherit system extraPythonPackages extraPackages;
            name = "${name}-env";
          };
        in
        pkgs.mkShell {
          packages = [ smallworldEnv ] ++ packages;
          inherit env shellHook;
        };

      # Build a Python interpreter whose package set exposes SmallWorld as
      # `ps.smallworld`, so downstream flakes can keep using
      # `python.withPackages` without importing a global overlay.
      mkDownstreamPython =
        {
          pkgs,
          system ? pkgs.stdenv.hostPlatform.system,
          python ? pkgs.python312,
          # Include the emulator backends downstream users usually expect from
          # `ps.smallworld`. angr only supports Python 3.10+, so leave it out
          # automatically on older interpreters.
          smallworldExtras ? (
            [
              "emu-ghidra"
              "emu-panda"
              "emu-unicorn"
            ]
            ++ lib.optional (lib.versionAtLeast python.pythonVersion "3.10") "emu-angr"
          ),
          packageOverrides ? (_: _: { }),
        }:
        let
          pythonSet = mkPythonSet {
            inherit system pkgs python;
          };
          pythonWithSmallworld = python.override {
            packageOverrides = lib.composeExtensions (
              py-final: _py-prev:
              let
                # Resolve the full transitive dependency closure of one locked
                # package from the uv2nix package set. Each dependency entry maps
                # a package name to the extras that must be enabled on that
                # dependency, so recurse through both direct dependencies and the
                # enabled optional dependency groups.
                resolveLockedDependencyNames =
                  name: enabledExtras:
                  let
                    rawPkg = pythonSet.${name};
                    selectedDeps = lib.zipAttrsWith (_name: extrasLists: lib.unique (lib.flatten extrasLists)) (
                      [ (rawPkg.dependencies or { }) ]
                      ++ map (extra: rawPkg.optional-dependencies.${extra} or { }) enabledExtras
                    );
                    depNames = builtins.attrNames selectedDeps;
                  in
                  lib.unique (
                    depNames
                    ++ lib.flatten (
                      map (depName: resolveLockedDependencyNames depName selectedDeps.${depName}) depNames
                    )
                  );

                rawSmallworld = pythonSet.smallworld-re;
                pypandaModule = if pythonSet ? pypanda then py-final.toPythonModule pythonSet.pypanda else null;
                smallworldDepNames = resolveLockedDependencyNames "smallworld-re" smallworldExtras;
                # uv2nix records runtime Python dependencies in a `dependencies`
                # attrset. Convert that closure into propagated Python module
                # dependencies so `python.withPackages` can import SmallWorld
                # with its transitive imports available. PANDA is excluded from
                # uv.lock, so add the locally built pypanda module by hand when
                # the downstream interpreter asks for that extra.
                smallworldDeps =
                  map (name: py-final.toPythonModule pythonSet.${name}) smallworldDepNames
                  ++ lib.optional (builtins.elem "emu-panda" smallworldExtras && pypandaModule != null) pypandaModule;
                smallworldModule = py-final.toPythonModule (
                  rawSmallworld.overrideAttrs (old: {
                    propagatedBuildInputs = (old.propagatedBuildInputs or [ ]) ++ smallworldDeps;
                  })
                );
              in
              {
                # Provide both names so downstream code can choose the nicer
                # `ps.smallworld` spelling while still matching the package name.
                smallworld = smallworldModule;
                "smallworld-re" = smallworldModule;
              }
            ) packageOverrides;
          };
        in
        pythonWithSmallworld
        // {
          withPackages =
            packageSelector:
            let
              baseEnv = pythonWithSmallworld.withPackages packageSelector;
            in
            pkgs.symlinkJoin {
              name = baseEnv.name;
              paths = [ baseEnv ];
              nativeBuildInputs = [ pkgs.makeWrapper ];
              postBuild = ''
                mkdir -p "$out/nix-support"
                if [ -f "${baseEnv}/nix-support/setup-hook" ]; then
                  cat "${baseEnv}/nix-support/setup-hook" > "$out/nix-support/setup-hook"
                else
                  : > "$out/nix-support/setup-hook"
                fi

                cat >> "$out/nix-support/setup-hook" <<'EOF'
                export GHIDRA_INSTALL_DIR=${ghidraInstallDir pkgs.ghidra}
                EOF

                for python_bin in "$out"/bin/python*; do
                  if [ -f "$python_bin" ] && [ -x "$python_bin" ]; then
                    wrapProgram "$python_bin" \
                      --set-default GHIDRA_INSTALL_DIR ${ghidraInstallDir pkgs.ghidra}
                  fi
                done
              '';
            };
        };

      # =====================================================================
      # Optional: Binary Ninja
      # =====================================================================

      bnUltimate = forAllSystems (
        system:
        if binaryninja != null && binjaZip != null then
          let
            bnPkgs = binaryninja.packages.${system};
          in
          bnPkgs.binary-ninja-ultimate-wayland.override { overrideSource = binjaZip; }
        else
          null
      );

    in
    {

      # =====================================================================
      # devShells — enter with `nix develop`
      # =====================================================================

      devShells = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;

          # The dev shell uses the same locked Python environment as the
          # package output, plus a few developer-only tools.
          virtualenv = mkLockedVirtualenv system "smallworld-re-dev-env" devDeps;

          defaultShell = pkgs.mkShell {
            packages = [
              virtualenv
              pkgs.uv
              pkgs.nixfmt
              pkgs.nixfmt-tree
            ]
            ++ toolDeps.${system}
            ++ lib.optional (bnUltimate.${system} != null) bnUltimate.${system};

            env = {
              GHIDRA_INSTALL_DIR = ghidraInstallDir pkgs.ghidra;
            };

            hardeningDisable = [ "all" ];

            shellHook = ''
              unset PYTHONPATH
              export REPO_ROOT=$(git rev-parse --show-toplevel)
            ''
            + lib.optionalString (bnUltimate.${system} != null) ''

              export BINJA_PATH=${bnUltimate.${system}}
              export PYTHONPATH=${bnUltimate.${system}}/opt/binaryninja/python:$PYTHONPATH
            '';
          };
        in
        {
          default = defaultShell;
          # Alias so shebangs like `nix develop .#pythonEnv` keep working.
          pythonEnv = defaultShell;
        }
      );

      # =====================================================================
      # Packages — build with `nix build .#<name>`
      # =====================================================================

      packages = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
          pythonSet = pythonSets.${system};
          virtualenv = mkLockedVirtualenv system "smallworld-re-env" runtimeDeps;
          smallworldEnv = mkDownstreamEnv {
            inherit system;
            name = "smallworld-re-env";
          };

          # Helper used by CI/debugging to print the full flake input closure.
          printInputsRecursive = pkgs.writers.writePython3Bin "print-inputs-recursive" { } ''
            import json
            import subprocess

            obj = json.loads(
                subprocess.check_output(["nix", "flake", "archive", "--json"])
            )


            def print_node(node):
                path = node.get("path")
                if path:
                    print(path)
                for _, input_node in (node.get("inputs") or {}).items():
                    print_node(input_node)


            print_node(obj)
          '';

          basePackages = {
            inherit printInputsRecursive;

            # `nix build` with no target gives you the assembled runtime env.
            default = smallworldEnv;
            inherit smallworldEnv;

            # If you want just the Python package artifact, build this target
            # explicitly with: nix build .#smallworld-re
            "smallworld-re" = pythonSet.smallworld-re;

            # Kept as a convenience when only the Python virtualenv is needed.
            venv = virtualenv;

            # Docker image containing smallworld + all tools.
            dockerImage =
              let
                bn = bnUltimate.${system};
                hasBinja = bn != null;
              in
              pkgs.dockerTools.buildImage {
                name = "smallworld-re";
                tag = "latest";
                copyToRoot = pkgs.buildEnv {
                  name = "smallworld-root";
                  paths = [
                    pkgs.dockerTools.usrBinEnv
                    pkgs.dockerTools.binSh
                    pkgs.dockerTools.caCertificates
                    pkgs.dockerTools.fakeNss
                    pkgs.coreutils
                    pkgs.unzip
                    pkgs.dbus.lib
                    pkgs.stdenv.cc.cc.lib
                    virtualenv
                  ]
                  ++ toolDeps.${system}
                  ++ lib.optional hasBinja bn;
                  pathsToLink = [
                    "/bin"
                    "/etc"
                    "/var"
                    "/lib"
                  ]
                  ++ lib.optional hasBinja "/opt";
                };
                config = {
                  Cmd = [ "/bin/sh" ];
                  Env = [
                    "LD_LIBRARY_PATH=/lib"
                    "GHIDRA_INSTALL_DIR=${ghidraInstallDir pkgs.ghidra}"
                    "JAVA_HOME=${pkgs.jre}"
                  ];
                };
              };
          };
        in
        basePackages
        // lib.optionalAttrs (bnUltimate.${system} != null) {
          binaryninja-ultimate = bnUltimate.${system};
        }
      );

      # A small helper library for downstream flakes.
      lib = {
        # Build the standard SmallWorld runtime environment, optionally with
        # extra nixpkgs Python packages layered on top.
        mkEnv = mkDownstreamEnv;

        # Build a simple development shell around the standard runtime
        # environment, with optional extra Python packages and shell tools.
        mkShell = mkDownstreamShell;

        # Build a Python interpreter whose `python.pkgs` set includes
        # `smallworld`, without mutating the caller's nixpkgs import.
        mkPython = mkDownstreamPython;
      };

      formatter = forAllSystems (system: (pkgsFor system).nixfmt);
    };
}
