{
  description = "smallworld-re";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixpkgs-unstable";

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

    panda-qemu = {
      url = "github:panda-re/qemu?ref=wrapup-rebase";
      flake = false;
    };

    panda-ng = {
      url = "github:rehostingdev/panda-ng?ref=nix-flake-init"; # TODO: update once PR is merged
      inputs.panda-qemu-src.follows = "panda-qemu";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    nixpkgs-esp-dev = {
      url = "github:mirrexagon/nixpkgs-esp-dev";
      flake = false;
    };

    # For building RTOS Demo
    zephyr = {
      url = "github:zephyrproject-rtos/zephyr/v3.5.0";
      flake = false;
    };

    zephyr-nix = {
      url = "github:adisbladis/zephyr-nix";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.zephyr.follows = "zephyr";
    };

    west2nix = {
      url = "github:adisbladis/west2nix";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.zephyr-nix.follows = "zephyr-nix";
    };
  };

  outputs =
    {
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
      systems = lib.systems.flakeExposed;
      forAllSystems = lib.genAttrs systems;

      pkgsFor = system: nixpkgs.legacyPackages.${system};

      # The default Python version used by this flake's top-level packages + shells.
      # Other versions are additionally exposed via packages/devShells and overlays.
      defaultPythonAttr = "python312";

      # All python interpreter attrs in nixpkgs that look like: python39, python310, python311, ...
      # (i.e. exactly "python3" + digits).
      pythonAttrsFor =
        pkgs: lib.filter (n: builtins.match "^python3[0-9]+$" n != null) (lib.attrNames pkgs);

      ghidraInstallDir = ghidra: "${ghidra}/lib/ghidra";

      patchedUnicornSpec = {
        owner = "appleflyerv3";
        repo = "unicorn";
        rev = "mmio_map_pc_sync";
        hash = "sha256-0MH+JS/mPESnTf21EOfGbuVrrrxf1i8WzzwzaPeCt1w=";
      };

      # Helpers shared between the uv2nix "prebuilts" overlay and the nixpkgs python overlay.
      pypandaBuilderFor = system: panda-ng.lib.${system}.pypandaBuilder;

      mkUnicornaflBuilder = callPackage: callPackage ./unicornafl-build { };

      mkPatchedUnicorn =
        {
          fetchFromGitHub,
          unicornLib,
          unicornPy,
        }:
        let
          patchedSrc = fetchFromGitHub patchedUnicornSpec;
          unicornLibPatched = unicornLib.overrideAttrs (_: {
            src = patchedSrc;
          });
        in
        unicornPy.override {
          unicorn = unicornLibPatched;
        };

      mkPythonNativeAddons =
        {
          system,
          fetchFromGitHub,
          unicornLib,
          unicornPy,
          callPackage,
          pythonPkgs,
        }:
        let
          mkUnicornafl = mkUnicornaflBuilder callPackage;
        in
        {
          unicorn = mkPatchedUnicorn { inherit fetchFromGitHub unicornLib unicornPy; };
          unicornafl = mkUnicornafl pythonPkgs;
          pypanda = (pypandaBuilderFor system) pythonPkgs qemu.${system};
        };

      # Workspace source selection: only the files needed to build the python project.
      root = ./.;
      fileset = lib.fileset.unions [
        ./pyproject.toml
        ./uv.lock
        ./.python-version
        ./smallworld
      ];
      rootString = builtins.unsafeDiscardStringContext (
        lib.fileset.toSource {
          inherit fileset root;
        }
      );
      rootPath = /. + rootString;

      workspace = uv2nix.lib.workspace.loadWorkspace { workspaceRoot = rootPath; };
      emptyDeps = lib.genAttrs [ "unicornafl" "pypanda" "colorama" "unicorn" ] (_: [ ]);
      deps = workspace.deps.all // emptyDeps;

      # Canonical QEMU derivation.
      qemu = forAllSystems (
        system:
        let
          qemuBase = panda-ng.packages.${system}.qemu;
        in
        qemuBase.overrideAttrs (old: {
          qemuSubprojects = old.qemuSubprojects.overrideAttrs (_: {
            outputHash = "sha256-eUw7yBWxRKJbfhKvZDRNpTSaxrnDYr31Tkx35Myx4Fs=";
          });
        })
      );

      # Python interpreters available in this nixpkgs (filtered).
      pythons = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
        in
        lib.genAttrs (pythonAttrsFor pkgs) (pyAttr: pkgs.${pyAttr})
      );

      # Name helpers: keep default names stable, suffix non-default envs for clarity.
      mkDevEnvName =
        pyAttr:
        if pyAttr == defaultPythonAttr then "smallworld-re-dev-env" else "smallworld-re-dev-env-${pyAttr}";

      mkProdEnvName =
        pyAttr: if pyAttr == defaultPythonAttr then "smallworld-re-env" else "smallworld-re-env-${pyAttr}";

      prebuiltsAll = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
          pyAttrs = pythonAttrsFor pkgs;
        in
        lib.genAttrs pyAttrs (
          pyAttr: _final: _prev:
          let
            python = pythons.${system}.${pyAttr};
            hacks = pkgs.callPackage pyproject-nix.build.hacks { };

            native = mkPythonNativeAddons {
              inherit system;
              fetchFromGitHub = pkgs.fetchFromGitHub;
              unicornLib = pkgs.unicorn;
              unicornPy = python.pkgs.unicorn;
              callPackage = pkgs.callPackage;
              pythonPkgs = python.pkgs;
            };
          in
          {
            unicorn = hacks.nixpkgsPrebuilt { from = native.unicorn; };
            unicornafl = hacks.nixpkgsPrebuilt { from = native.unicornafl; };
            pypanda = hacks.nixpkgsPrebuilt { from = native.pypanda; };

            colorama = hacks.nixpkgsPrebuilt { from = python.pkgs.colorama; };
          }
        )
      );

      # Keep the original output/shape for `prebuilts` (default python).
      prebuilts = forAllSystems (system: prebuiltsAll.${system}.${defaultPythonAttr});

      overlay = workspace.mkPyprojectOverlay { sourcePreference = "wheel"; };
      editableOverlay = workspace.mkEditablePyprojectOverlay { root = "$REPO_ROOT"; };

      pythonSetsByPython = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
          pyAttrs = pythonAttrsFor pkgs;
        in
        lib.genAttrs pyAttrs (
          pyAttr:
          let
            python = pythons.${system}.${pyAttr};
            overrides = pkgs.callPackage ./overrides.nix { inherit python; };

            pyprojectPkgs = pkgs.callPackage pyproject-nix.build.packages { inherit python; };
          in
          pyprojectPkgs.overrideScope (
            lib.composeManyExtensions [
              pyproject-build-systems.overlays.wheel
              overlay
              overrides
              prebuiltsAll.${system}.${pyAttr}
            ]
          )
        )
      );

      # Keep the original output/shape for `pythonSet` (default python).
      pythonSetDefault = forAllSystems (system: pythonSetsByPython.${system}.${defaultPythonAttr});

      virtualEnvDevByPython = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
          pyAttrs = pythonAttrsFor pkgs;
        in
        lib.genAttrs pyAttrs (
          pyAttr:
          let
            pythonSet = pythonSetsByPython.${system}.${pyAttr}.overrideScope editableOverlay;
          in
          pythonSet.mkVirtualEnv (mkDevEnvName pyAttr) deps
        )
      );

      virtualEnvProdByPython = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
          pyAttrs = pythonAttrsFor pkgs;
        in
        lib.genAttrs pyAttrs (
          pyAttr:
          let
            pythonSet = pythonSetsByPython.${system}.${pyAttr};
          in
          pythonSet.mkVirtualEnv (mkProdEnvName pyAttr) deps
        )
      );

      # Keep the original output/shape for the venvs used by top-level outputs.
      virtualEnvDev = forAllSystems (system: virtualEnvDevByPython.${system}.${defaultPythonAttr});
      virtualEnvProd = forAllSystems (system: virtualEnvProdByPython.${system}.${defaultPythonAttr});
    in
    rec {
      devShells = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
          pyAttrs = pythonAttrsFor pkgs;

          toolInputs = [
            pkgs.z3
            pkgs.aflplusplus
            qemu.${system}
            pkgs.ghidra
            pkgs.jdk
          ];

          GHIDRA_INSTALL_DIR = ghidraInstallDir pkgs.ghidra;

          pythonEnvPkgs = import nixpkgs {
            inherit system;
            overlays = [ overlays.default ];
          };

          mkShellsFor =
            pyAttr:
            let
              pythonSet = pythonSetsByPython.${system}.${pyAttr}.overrideScope editableOverlay;
              virtualenv = virtualEnvDevByPython.${system}.${pyAttr};

              # Used by the imperative shell's PYTHONPATH.
              smallworldBuilt = pythonSetsByPython.${system}.${pyAttr}.smallworld-re;

              pythonEnv = pythonEnvPkgs.mkShell {
                packages = [
                  (pythonEnvPkgs.${pyAttr}.withPackages (ps: [ ps.smallworld ]))
                ];
              };

              defaultShell = pkgs.mkShell {
                packages = [
                  virtualenv
                  pkgs.uv
                  pkgs.nixfmt
                  pkgs.nixfmt-tree
                ]
                ++ toolInputs;

                env = {
                  inherit GHIDRA_INSTALL_DIR;
                  UV_NO_SYNC = "1";
                  UV_PYTHON = pythonSet.python.interpreter;
                  UV_PYTHON_DOWNLOADS = "never";
                };

                hardeningDisable = [ "all" ];

                shellHook = ''
                  unset PYTHONPATH
                  export REPO_ROOT=$(git rev-parse --show-toplevel)
                '';
              };

              imperativeShell = pkgs.mkShell {
                packages = [
                  pythonSet.python
                  pythonSet.pip
                  pythonSet.setuptools
                ]
                ++ toolInputs;

                env = {
                  inherit GHIDRA_INSTALL_DIR;
                };

                shellHook = ''
                  export PYTHONPATH="${smallworldBuilt}/${pythonSet.python.sitePackages}:${virtualenv}/${pythonSet.python.sitePackages}:$PYTHONPATH"
                  unset SOURCE_DATE_EPOCH
                '';
              };
            in
            {
              inherit pythonEnv;
              default = defaultShell;
              imperative = imperativeShell;
            };

          defaultShells = mkShellsFor defaultPythonAttr;
        in
        {
          # Preserve original names/behavior.
          inherit (defaultShells) pythonEnv default imperative;

          # Additional Python versions.
          pythonEnvByPython = lib.genAttrs pyAttrs (pyAttr: (mkShellsFor pyAttr).pythonEnv);
          defaultByPython = lib.genAttrs pyAttrs (pyAttr: (mkShellsFor pyAttr).default);
          imperativeByPython = lib.genAttrs pyAttrs (pyAttr: (mkShellsFor pyAttr).imperative);
        }
      );

      packages = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
          pyAttrs = pythonAttrsFor pkgs;

          pythonSet = pythonSetDefault.${system};
          virtualenv = virtualEnvProd.${system};

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

          x86_64_glibc_path = pkgs.glibc.outPath;
          xtensaGcc = pkgs.callPackage "${nixpkgs-esp-dev}/pkgs/esp8266/gcc-xtensa-lx106-elf-bin.nix" { };

          tests = pkgs.callPackage ./tests {
            inherit xtensaGcc x86_64_glibc_path;
          };

          rtos_demo = pkgs.callPackage ./use_cases/rtos_demo {
            zephyr = zephyr-nix.packages.${system};
            west2nix = pkgs.callPackage west2nix.lib.mkWest2nix { };
          };

          packagesByPython = lib.genAttrs pyAttrs (
            pyAttr: pythonSetsByPython.${system}.${pyAttr}.smallworld-re
          );
          venvsByPython = lib.genAttrs pyAttrs (pyAttr: virtualEnvProdByPython.${system}.${pyAttr});
        in
        {
          inherit printInputsRecursive tests rtos_demo;

          # Preserve original names/behavior.
          default = pythonSet.smallworld-re;
          venv = virtualenv;
          qemu = qemu.${system};

          dockerImage = pkgs.dockerTools.buildImage {
            name = "smallworld-re";
            tag = "latest";
            copyToRoot = pkgs.buildEnv {
              name = "smallworld-root";
              paths = [
                pkgs.dockerTools.usrBinEnv
                pkgs.dockerTools.binSh
                pkgs.dockerTools.caCertificates
                pkgs.dockerTools.fakeNss
                pkgs.aflplusplus
                qemu.${system}
                virtualenv
                pkgs.ghidra
              ];
              pathsToLink = [
                "/bin"
                "/etc"
                "/var"
              ];
            };
            config = {
              Cmd = [ "/bin/sh" ];
            };
          };

          # Additional Python versions.
          byPython = packagesByPython;
          venvByPython = venvsByPython;
        }
      );

      # Preserve original outputs.
      pythonSet = forAllSystems (system: pythonSetDefault.${system});
      pythonDeps = deps;
      inherit prebuilts;

      # New: expose all python sets/prebuilts.
      pythonSets = pythonSetsByPython;
      prebuiltsByPython = prebuiltsAll;

      # Nixpkgs overlay that exposes `smallworld` as a normal Python package usable via:
      #   pkgs.python312.withPackages (ps: [ ps.smallworld ])
      # and similarly for other supported Python versions.
      overlays.default =
        final: prev:
        let
          system = final.stdenv.hostPlatform.system;

          # Only expose versions for which this flake can provide a matching pythonSet.
          pyAttrs = lib.filter (n: builtins.hasAttr n (pythonSetsByPython.${system})) (pythonAttrsFor prev);

          toolDeps = [
            qemu.${system}
            final.aflplusplus
            final.z3
          ];

          pkgToolDeps = [
            final.ghidra
            final.jre
          ]
          ++ toolDeps;
          envToolDeps = [
            final.jre
            final.ghidra
          ]
          ++ toolDeps;

          pythonAddonDepsFor = pyFinal: [
            pyFinal.pyghidra
            pyFinal.pypanda
            pyFinal.unicornafl
            pyFinal.unicorn
          ];

          mkPythonFor =
            pyAttr:
            let
              # The pyproject-nix/uv2nix package set built by this flake for the current system.
              pythonSet = pythonSetsByPython.${system}.${pyAttr};

              hacks = final.callPackage pyproject-nix.build.hacks { };

              # IMPORTANT:
              # `hacks.toNixpkgs` works by enabling a wheel ("dist") output and then using the
              # generated wheel as input to nixpkgs `buildPythonPackage`. This generally FAILS
              # for packages pulled in via `hacks.nixpkgsPrebuilt` (e.g. unicorn/pypanda/
              # unicornafl), because those do not produce wheels.
              basePyOverlay = hacks.toNixpkgs {
                inherit pythonSet;
                packages = [
                  "smallworld-re"
                  "pyghidra"
                  "pypcode"
                ];
              };

              convertedOverlay =
                pyFinal: pyPrev:
                let
                  converted = basePyOverlay pyFinal pyPrev;

                  # Make `smallworld` (and `smallworld-re`) automatically pull in heavy/native
                  # add-ons that downstream users often expect.
                  smallworldWithAllDeps = (converted."smallworld-re").overridePythonAttrs (old: {
                    propagatedBuildInputs =
                      (old.propagatedBuildInputs or [ ]) ++ ((pythonAddonDepsFor pyFinal) ++ pkgToolDeps);
                  });
                in
                converted
                // {
                  "smallworld-re" = smallworldWithAllDeps;
                  smallworld = smallworldWithAllDeps;
                };

              extraOverlay =
                pyFinal: pyPrev:
                let
                  native = mkPythonNativeAddons {
                    inherit system;
                    fetchFromGitHub = final.fetchFromGitHub;
                    unicornLib = prev.unicorn;
                    unicornPy = pyPrev.unicorn;
                    callPackage = final.callPackage;
                    pythonPkgs = pyFinal;
                  };
                in
                {
                  inherit (native) unicorn unicornafl pypanda;
                };

              # IMPORTANT: keep the overlay composition order.
              pyOverlay = final.lib.composeExtensions convertedOverlay extraOverlay;

              basePython = prev.${pyAttr}.override (old: {
                self = basePython;
                packageOverrides = final.lib.composeExtensions (old.packageOverrides or (_: _: { })) pyOverlay;
              });

              # Wrap `withPackages` so the resulting python env derivation contains a setup-hook.
              python = basePython // {
                withPackages =
                  f:
                  let
                    env = basePython.withPackages f;
                    requested = f basePython.pkgs;
                    needsGhidra = final.lib.any (
                      p:
                      let
                        pname = p.pname or null;
                      in
                      pname == "smallworld-re" || pname == "pyghidra" || pname == "smallworld"
                    ) requested;
                  in
                  if needsGhidra then
                    final.buildEnv {
                      name = "${env.name}-smallworld-full";

                      # Tool deps included here so they land on PATH in downstream shells.
                      paths = [ env ] ++ envToolDeps;

                      pathsToLink = [
                        "/bin"
                        "/nix-support"
                      ];
                      ignoreCollisions = true;

                      postBuild = ''
                        # Ensure nix-support is a real directory (not a symlink from an input).
                        if [ -L "$out/nix-support" ]; then
                          rm -f "$out/nix-support"
                        fi
                        mkdir -p "$out/nix-support"

                        # If buildEnv linked an existing setup-hook as a symlink, replace it.
                        if [ -e "$out/nix-support/setup-hook" ]; then
                          rm -f "$out/nix-support/setup-hook"
                        fi

                        # Preserve any setup-hook content from the underlying python env, if present.
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

          pythonOverrides = lib.genAttrs pyAttrs mkPythonFor;

          pythonPackagesAttrs = lib.listToAttrs (
            map (pyAttr: {
              name = "${pyAttr}Packages";
              value = final.${pyAttr}.pkgs;
            }) pyAttrs
          );
        in
        pythonOverrides // pythonPackagesAttrs;

      formatter = forAllSystems (system: (pkgsFor system).nixfmt);
    };
}
