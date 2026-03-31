# Nix flake for smallworld-re.
#
# This file has one job: turn the Python project described by
#   - pyproject.toml
#   - uv.lock
# into:
#   - a ready-to-use package (`nix build`)
#   - a development shell (`nix develop`)
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

    # Xtensa cross-compiler (used only for building test binaries).
    nixpkgs-esp-dev = {
      url = "github:mirrexagon/nixpkgs-esp-dev";
      flake = false;
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

    # Zephyr RTOS tooling (used only for the rtos_demo use-case).
    zephyr-nix = {
      url = "github:adisbladis/zephyr-nix";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.pyproject-nix.follows = "pyproject-nix";
    };
    west2nix = {
      url = "github:adisbladis/west2nix";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.zephyr-nix.follows = "zephyr-nix";
    };
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
      nixpkgs-esp-dev,
      zephyr-nix,
      west2nix,
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

      # Load every dependency group from pyproject.toml. For the packages we
      # build ourselves below, give uv2nix an empty placeholder so it does not
      # also try to fetch them from PyPI.
      prebuiltNames = [
        "unicornafl"
        "pypanda"
        "unicorn"
      ];
      deps = workspace.deps.all // lib.genAttrs prebuiltNames (_: [ ]);

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

      # Convert the native packages above into the format uv2nix expects for
      # already-built Python packages.
      nativePrebuilts = forAllSystems (
        system: _final: _prev:
        let
          pkgs = pkgsFor system;
          python = basePython.${system};
          hacks = pkgs.callPackage pyproject-nix.build.hacks { };
          native = pythonNativeAddons.${system} {
            pythonPkgs = python.pkgs;
            unicornPy = python.pkgs.unicorn;
          } pkgs;
        in
        {
          unicorn = hacks.nixpkgsPrebuilt { from = native.unicorn; };
          unicornafl = hacks.nixpkgsPrebuilt { from = native.unicornafl; };
          pypanda = hacks.nixpkgsPrebuilt { from = native.pypanda; };
        }
      );

      # =====================================================================
      # This is the final locked Python package set:
      #   1. standard Python build tools
      #   2. packages from uv.lock
      #   3. local fixes from overrides.nix
      #   4. the native packages we build ourselves
      #
      # `overrideScope` is the standard Nix way to layer package-set changes.
      # Read it as: start with the uv2nix package set, then apply these
      # adjustments in order.
      # =====================================================================

      pythonSets = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
          python = basePython.${system};
          pyprojectPkgs = pkgs.callPackage pyproject-nix.build.packages { inherit python; };
        in
        pyprojectPkgs.overrideScope (
          lib.composeManyExtensions [
            pyproject-build-systems.overlays.wheel
            (workspace.mkPyprojectOverlay { sourcePreference = "wheel"; })
            (pkgs.callPackage ./overrides.nix { inherit python; })
            nativePrebuilts.${system}
          ]
        )
      );

      # =====================================================================
      # Non-Python tools smallworld expects to find on PATH.
      # =====================================================================

      toolDeps = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
        in
        [
          pkgs.aflplusplus
          pkgs.z3
          pkgs.ghidra
          pkgs.jdk
        ]
      );

      # Build the runtime environment we want downstream users to consume:
      # the locked Python virtualenv plus the native tools smallworld needs.
      mkSmallworldEnv =
        {
          system,
          pkgs,
          env,
          name ? "${env.name}-smallworld-full",
        }:
        pkgs.buildEnv {
          inherit name;
          paths = [ env ] ++ toolDeps.${system};
          pathsToLink = [
            "/bin"
            "/nix-support"
          ];
          ignoreCollisions = true;

          postBuild = ''
            # Keep the virtualenv setup hook, then append the extra runtime
            # variables smallworld expects.
            if [ -L "$out/nix-support" ]; then rm -f "$out/nix-support"; fi
            mkdir -p "$out/nix-support"
            if [ -e "$out/nix-support/setup-hook" ]; then rm -f "$out/nix-support/setup-hook"; fi
            if [ -f "${env}/nix-support/setup-hook" ]; then
              cat "${env}/nix-support/setup-hook" > "$out/nix-support/setup-hook"
            else
              : > "$out/nix-support/setup-hook"
            fi
            cat >> "$out/nix-support/setup-hook" <<'EOF'
            export GHIDRA_INSTALL_DIR=${ghidraInstallDir pkgs.ghidra}
            export JAVA_HOME=${pkgs.jdk}
            EOF
          '';
        };

      # Build a Python virtualenv directly from the locked package set.
      # This is the "Python only" environment before we add non-Python tools.
      mkLockedVirtualenv = system: name: pythonSets.${system}.mkVirtualEnv name deps;

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
          virtualenv = mkLockedVirtualenv system "smallworld-re-dev-env";

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
          virtualenv = mkLockedVirtualenv system "smallworld-re-env";
          smallworldEnv = mkSmallworldEnv {
            inherit system pkgs;
            env = virtualenv;
            name = "smallworld-re-env";
          };

          # Helper used by CI/debugging to print the full flake input closure.
          printInputsRecursive = pkgs.writers.writePython3Bin "print-inputs-recursive" { } ''
            import json
            import subprocess

            obj = json.loads(subprocess.check_output(["nix", "flake", "archive", "--json"]))


            def print_node(node):
                path = node.get("path")
                if path:
                    print(path)
                for _, input_node in (node.get("inputs") or {}).items():
                    print_node(input_node)


            print_node(obj)
          '';

          xtensaGcc = pkgs.callPackage "${nixpkgs-esp-dev}/pkgs/esp8266/gcc-xtensa-lx106-elf-bin.nix" { };

          tests = pkgs.callPackage ./tests {
            inherit xtensaGcc;
            x86_64_glibc_path = pkgs.glibc.outPath;
          };

          rtos_demo = pkgs.callPackage ./use_cases/rtos_demo {
            zephyr = zephyr-nix.packages.${system};
            west2nix = pkgs.callPackage west2nix.lib.mkWest2nix { };
          };

          basePackages = {
            inherit printInputsRecursive tests rtos_demo;

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

      formatter = forAllSystems (system: (pkgsFor system).nixfmt);
    };
}
