# Nix flake for smallworld-re.
#
# Key concepts for beginners:
#   - A "flake" is a nix project with pinned dependencies (inputs) and defined outputs.
#   - "inputs" are other flakes/repos this project depends on.
#   - "outputs" are what this flake provides: dev shells, packages, overlays, etc.
#   - `forAllSystems` makes every output work on linux, macOS, etc.
#   - Python deps come from pyproject.toml + uv.lock via uv2nix -- not hardcoded here.
#   - A few Python packages (the patched version of unicorn, pypanda, etc.) need native C libraries and can't be
#     installed from wheels, so they are built from source as "prebuilts".
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
  # Outputs — what this flake provides to the world.
  # ==========================================================================
  outputs =
    inputs@{
      self,
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

      # Generate an attribute set with one entry per supported system
      # (x86_64-linux, aarch64-linux, x86_64-darwin, etc.).
      systems = lib.systems.flakeExposed;
      forAllSystems = lib.genAttrs systems;

      # Shorthand to get nixpkgs for a given system.
      pkgsFor = system: nixpkgs.legacyPackages.${system};

      # Optional Binary Ninja inputs (null when commented out above).
      binaryninja = inputs.binaryninja or null;
      binjaZip = inputs.binjaZip or null;

      # Helper: given a ghidra derivation, return its install directory.
      ghidraInstallDir = ghidra: "${ghidra}/lib/ghidra";

      # =====================================================================
      # Python workspace — reads pyproject.toml + uv.lock via uv2nix.
      # All Python dependency information lives in those files, not here.
      # =====================================================================

      # Only copy the files uv2nix needs into the nix store (avoids
      # rebuilding when unrelated files change).
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

      # The full dependency specification from pyproject.toml (including dev
      # and optional groups like emu-angr, emu-ghidra, etc.).
      # "prebuiltNames" are packages we build from source (not from wheels),
      # so we give them empty dependency lists to avoid uv2nix trying to
      # fetch them from PyPI.
      prebuiltNames = [
        "unicornafl"
        "pypanda"
        "unicorn"
      ];
      deps = workspace.deps.all // lib.genAttrs prebuiltNames (_: [ ]);

      # =====================================================================
      # Native Python packages — these need C/C++ compilation and can't come
      # from wheels. We build them from source and inject them as "prebuilts"
      # into the uv2nix package set.
      # =====================================================================

      basePython = forAllSystems (system: (pkgsFor system).python312);

      # Build a patched unicorn (fixes MIPS bug), unicornafl, and pypanda
      # for the target system's Python. Returns a function that takes
      # { pythonPkgs, unicornPy } and then nixpkgs, producing the three packages.
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

      # Wrap the native addons as uv2nix "prebuilts" so they slot into the
      # uv2nix package set alongside the packages built from wheels.
      prebuilts = forAllSystems (
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
      # Python package set — the final set combining:
      #   1. Standard build systems (setuptools, etc.) from pyproject-build-systems
      #   2. Packages resolved from pyproject.toml + uv.lock
      #   3. Build fixes for specific packages (overrides.nix)
      #   4. Native/prebuilt packages (unicorn, pypanda, etc.)
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
            prebuilts.${system}
          ]
        )
      );

      # =====================================================================
      # Non-Python tool dependencies — defined once, shared across the
      # devShell, overlay, and Docker image.
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
    # `rec` lets outputs reference each other (devShells uses overlays.default).
    rec {

      # =====================================================================
      # devShells — enter with `nix develop`
      # =====================================================================

      devShells = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;

          # A Python virtualenv with smallworld + all emulators + dev tools,
          # built from pyproject.toml via uv2nix.
          virtualenv = pythonSets.${system}.mkVirtualEnv "smallworld-re-dev-env" deps;

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
      # packages — build with `nix build .#<name>`
      # =====================================================================

      packages = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
          pythonSet = pythonSets.${system};
          virtualenv = pythonSet.mkVirtualEnv "smallworld-re-env" deps;

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
        in
        {
          inherit printInputsRecursive tests rtos_demo;

          # `nix build` with no target builds the smallworld Python package.
          default = pythonSet.smallworld-re;
          venv = virtualenv;

          binaryninja-ultimate = lib.optionalAttrs (bnUltimate.${system} != null) {
            default = bnUltimate.${system};
          };

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
        }
      );

      # =====================================================================
      # Nixpkgs overlay — lets downstream consumers do:
      #   pkgs.python312.withPackages (ps: [ ps.smallworld ])
      # =====================================================================

      overlays.default =
        final: prev:
        let
          system = final.stdenv.hostPlatform.system;
          pythonSet = pythonSets.${system};
          hacks = final.callPackage pyproject-nix.build.hacks { };

          # Convert selected uv2nix packages to nixpkgs format.
          # Only packages that don't exist in nixpkgs (or need the uv2nix
          # version) should be listed here. Converting ALL packages causes
          # infinite recursion because the converted versions conflict with
          # the nixpkgs originals' dependency graphs.
          # Prebuilts (unicorn, pypanda, etc.) are excluded because they
          # don't produce wheels — they're handled by nativeOverlay below.
          basePyOverlay = hacks.toNixpkgs {
            inherit pythonSet;
            packages = [
              "smallworld-re"
              # angr ecosystem (not in nixpkgs)
              "angr"
              "archinfo"
              "ailment"
              "claripy"
              "cle"
              "pyvex"
              # ghidra ecosystem (not in nixpkgs)
              "pyghidra"
              "pypcode"
              "pyxdia"
              # other deps not in nixpkgs
              "uefi-firmware"
            ];
          };

          # Overlay that converts uv2nix packages and patches angr/smallworld.
          convertedOverlay =
            pyFinal: pyPrev:
            let
              converted = basePyOverlay pyFinal pyPrev;

              # angr needs pyvex's shared lib on the linker search path.
              angrFixed = converted.angr.overridePythonAttrs (old: {
                postFixup = (old.postFixup or "") + ''
                  addAutoPatchelfSearchPath ${pyFinal.pyvex}
                '';
              });

              # Make `ps.smallworld` automatically pull in all emulator
              # backends and tool dependencies so downstream users get a
              # batteries-included experience.
              smallworldFull = (converted."smallworld-re").overridePythonAttrs (old: {
                propagatedBuildInputs =
                  (old.propagatedBuildInputs or [ ])
                  ++ (with pyFinal; [
                    pyghidra
                    pypanda
                    unicornafl
                    unicorn
                    angr
                  ])
                  ++ toolDeps.${system};
              });
            in
            converted
            // {
              angr = angrFixed;
              "smallworld-re" = smallworldFull;
              smallworld = smallworldFull;
            };

          # Overlay that injects the native/prebuilt packages (patched
          # unicorn, unicornafl, pypanda) into the nixpkgs Python set.
          nativeOverlay =
            pyFinal: pyPrev:
            let
              native = pythonNativeAddons.${system} {
                pythonPkgs = pyFinal;
                unicornPy = pyPrev.unicorn;
              } (final // { inherit (prev) unicorn; });
            in
            {
              inherit (native) unicorn unicornafl pypanda;
            };

          # Combine both overlays into one Python package overlay.
          pyOverlay = final.lib.composeExtensions convertedOverlay nativeOverlay;
        in
        {
          # Override python312 to include all smallworld packages.
          python312 =
            let
              # Inject our Python package overlay into the python312 package set.
              basePython = prev.python312.override (old: {
                self = basePython;
                packageOverrides = final.lib.composeExtensions (old.packageOverrides or (_: _: { })) pyOverlay;
              });

              # Wrap `withPackages` so that requesting smallworld/pyghidra
              # automatically adds tool deps to PATH and sets env vars.
              python = basePython // {
                withPackages =
                  f:
                  let
                    env = basePython.withPackages f;
                    requested = f basePython.pkgs;
                    needsTools = final.lib.any (
                      p:
                      let
                        pname = p.pname or null;
                      in
                      pname == "smallworld-re" || pname == "pyghidra" || pname == "smallworld"
                    ) requested;
                  in
                  if needsTools then
                    # Wrap the Python env in a buildEnv that also has the
                    # non-Python tools on PATH and sets GHIDRA_INSTALL_DIR.
                    final.buildEnv {
                      name = "${env.name}-smallworld-full";
                      paths = [ env ] ++ toolDeps.${system};
                      pathsToLink = [
                        "/bin"
                        "/nix-support"
                      ];
                      ignoreCollisions = true;

                      postBuild = ''
                        if [ -L "$out/nix-support" ]; then rm -f "$out/nix-support"; fi
                        mkdir -p "$out/nix-support"
                        if [ -e "$out/nix-support/setup-hook" ]; then rm -f "$out/nix-support/setup-hook"; fi
                        if [ -f "${env}/nix-support/setup-hook" ]; then
                          cat "${env}/nix-support/setup-hook" > "$out/nix-support/setup-hook"
                        else
                          : > "$out/nix-support/setup-hook"
                        fi
                        cat >> "$out/nix-support/setup-hook" <<'EOF'
                        export GHIDRA_INSTALL_DIR=${ghidraInstallDir final.ghidra}
                        export JAVA_HOME=${final.jre}
                        EOF
                      '';
                    }
                  else
                    env;
              };
            in
            python;

          python312Packages = final.python312.pkgs;
        };

      # =====================================================================
      # Exposed internals — used by downstream flakes and CI.
      # =====================================================================

      pythonSet = forAllSystems (system: pythonSets.${system});
      pythonDeps = deps;
      inherit prebuilts;

      formatter = forAllSystems (system: (pkgsFor system).nixfmt);
    };
}
