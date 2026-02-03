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
      url = "github:rehostingdev/panda-ng?ref=nix-flake-init"; # TODO update once PR is merged
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
      inherit (nixpkgs) lib;
      forAllSystems = lib.genAttrs lib.systems.flakeExposed;

      root = ./.;
      fileset = nixpkgs.lib.fileset.unions [
        ./pyproject.toml
        ./uv.lock
        ./.python-version
        ./smallworld
      ];
      rootString = builtins.unsafeDiscardStringContext (
        nixpkgs.lib.fileset.toSource { inherit fileset root; }
      );
      rootPath = (/. + rootString);
      workspace = uv2nix.lib.workspace.loadWorkspace { workspaceRoot = rootPath; };
      deps = workspace.deps.all // {
        unicornafl = [ ];
        pypanda = [ ];
        colorama = [ ];
        unicorn = [ ];
      };

      basePython = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          python = pkgs.python312;
        in
        python
      );

      prebuilts = forAllSystems (
        system: final: prev:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          python = basePython.${system};
          hacks = pkgs.callPackage pyproject-nix.build.hacks { };
          mkUnicornafl = pkgs.callPackage ./unicornafl-build { };

          patched-unicorn = pkgs.fetchFromGitHub {
            owner = "appleflyerv3";
            repo = "unicorn";
            rev = "mmio_map_pc_sync";
            hash = "sha256-0MH+JS/mPESnTf21EOfGbuVrrrxf1i8WzzwzaPeCt1w=";
          };
          unicornPatched = pkgs.unicorn.overrideAttrs (final: {
            src = patched-unicorn;
          });

          pyUnicornPatched = python.pkgs.unicorn.override {
            unicorn = unicornPatched;
          };
        in
        {
          unicorn = hacks.nixpkgsPrebuilt {
            from = pyUnicornPatched;
          };

          unicornafl = hacks.nixpkgsPrebuilt {
            from = (mkUnicornafl python.pkgs);
          };
          pypanda = hacks.nixpkgsPrebuilt {
            from = panda-ng.lib.${system}.pypandaBuilder python.pkgs qemu.${system};
          };
          colorama = hacks.nixpkgsPrebuilt {
            from = python.pkgs.colorama;
          };
        }
      );

      overlay = workspace.mkPyprojectOverlay {
        sourcePreference = "wheel";
      };

      editableOverlay = workspace.mkEditablePyprojectOverlay {
        root = "$REPO_ROOT";
      };

      pythonSets = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          python = basePython.${system};
          overrides = pkgs.callPackage ./overrides.nix { inherit python; };
        in
        (pkgs.callPackage pyproject-nix.build.packages {
          inherit python;
        }).overrideScope
          (
            lib.composeManyExtensions [
              pyproject-build-systems.overlays.wheel
              overlay
              overrides
              prebuilts.${system}
            ]
          )
      );

      virtualEnvDev = forAllSystems (
        system:
        let
          pythonSet = pythonSets.${system}.overrideScope editableOverlay;
          venv = pythonSet.mkVirtualEnv "smallworld-re-dev-env" deps;
        in
        venv
      );

      virtualEnvProd = forAllSystems (
        system:
        let
          pythonSet = pythonSets.${system};
          venv = pythonSet.mkVirtualEnv "smallworld-re-env" deps;
        in
        venv
      );

      qemu = forAllSystems (
        system:
        let
          qemu = panda-ng.packages.${system}.qemu.overrideAttrs (old: {
            qemuSubprojects = old.qemuSubprojects.overrideAttrs (old: {
              outputHash = "sha256-eUw7yBWxRKJbfhKvZDRNpTSaxrnDYr31Tkx35Myx4Fs=";
            });
          });
        in
        qemu
      );
    in
    rec {
      devShells = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          pythonSet = pythonSets.${system}.overrideScope editableOverlay;
          virtualenv = virtualEnvDev.${system};
          inputs = [
            pkgs.z3
            pkgs.aflplusplus
            qemu.${system}
            pkgs.ghidra
            pkgs.jdk
          ];
          GHIDRA_INSTALL_DIR = "${pkgs.ghidra}/lib/ghidra";
          smallworldBuilt = packages.${system}.default;
        in
        {
          default = pkgs.mkShell {
            packages = [
              virtualenv
              pkgs.uv
              pkgs.nixfmt
              pkgs.nixfmt-tree
            ]
            ++ inputs;
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
          imperative = pkgs.mkShell {
            packages = [
              pythonSet.python
              pythonSet.pip
              pythonSet.setuptools
            ]
            ++ inputs;
            env = {
              inherit GHIDRA_INSTALL_DIR;
            };
            shellHook = ''
              export PYTHONPATH="${smallworldBuilt}/${pythonSet.python.sitePackages}:${virtualenv}/${pythonSet.python.sitePackages}:$PYTHONPATH"
              unset SOURCE_DATE_EPOCH
            '';
          };
        }
      );

      packages = forAllSystems (
        system:
        let
          pythonSet = pythonSets.${system};
          pkgs = nixpkgs.legacyPackages.${system};
          virtualenv = virtualEnvProd.${system};

          printInputsRecursive = pkgs.writers.writePython3Bin "print-inputs-recursive" { } ''
            import subprocess
            import json
            s = subprocess.check_output(['nix', 'flake', 'archive', '--json'])
            obj = json.loads(s)


            def print_node(node):
                path = node.get("path")
                if path:
                    print(path)
                inputs = node.get("inputs")
                for input_name, input_node in inputs.items():
                    print_node(input_node)


            print_node(obj)
          '';

          x86_64_glibc_path = pkgs.glibc.outPath;
          xtensaGcc = pkgs.callPackage "${nixpkgs-esp-dev}/pkgs/esp8266/gcc-xtensa-lx106-elf-bin.nix" { };
          tests = pkgs.callPackage ./tests {
            inherit xtensaGcc;
            inherit x86_64_glibc_path;
          };
          rtos_demo = pkgs.callPackage ./use_cases/rtos_demo {
            zephyr = zephyr-nix.packages.${system};
            west2nix = pkgs.callPackage west2nix.lib.mkWest2nix { };
          };
        in
        {
          inherit printInputsRecursive tests rtos_demo;
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
        }
      );

      pythonSet = forAllSystems (system: pythonSets.${system});

      pythonDeps = deps;

      inherit prebuilts;

      # Nixpkgs overlay that exposes `smallworld` as a normal Python package
      # usable via `pkgs.python312.withPackages (ps: [ ps.smallworld ])`.
      overlays.default =
        final: prev:
        let
          system = final.stdenv.hostPlatform.system;

          # The pyproject-nix/uv2nix package set built by this flake for the
          # current system.
          pythonSet = pythonSets.${system};

          hacks = final.callPackage pyproject-nix.build.hacks { };

          # IMPORTANT:
          # `hacks.toNixpkgs` works by enabling a wheel ("dist") output and then
          # using the generated wheel as input to nixpkgs `buildPythonPackage`.
          # That *only* works for packages that are actually built by the
          # pyproject-nix/uv2nix builders. It will generally FAIL for packages
          # that you pulled in via `hacks.nixpkgsPrebuilt` (like unicorn/pypanda/
          # unicornafl in this repo), because those do not produce wheels.
          basePyOverlay = hacks.toNixpkgs {
            inherit pythonSet;
            packages = [ "smallworld-re" "pyghidra" "pypcode"];
          };

          # Wrap the converted set to add a nicer alias.
          convertedOverlay =
            pyFinal: pyPrev:
            let
              converted = basePyOverlay pyFinal pyPrev;

              # Make `smallworld` (and `smallworld-re`) automatically pull in
              # heavy/native add-ons that downstream users often expect.
              #
              # This is what makes `python.withPackages (ps: [ ps.smallworld ])`
              # also include `ps.pypanda` + `ps.unicornafl` in the environment.
              smallworldWithAllDeps =
                (converted."smallworld-re").overridePythonAttrs (old: {
                  propagatedBuildInputs =
                    (old.propagatedBuildInputs or [ ])
                    ++ [
                      # Python deps
                      pyFinal.pyghidra
                      pyFinal.pypanda
                      pyFinal.unicornafl
                      pyFinal.unicorn

                      # Native/runtime deps commonly required by these modules
                      final.ghidra
                      final.jre
                      qemu.${system}
                      final.aflplusplus
                      final.z3
                    ];
                });
            in
            converted
            // {
              # Keep the original attribute name, but with add-ons propagated.
              "smallworld-re" = smallworldWithAllDeps;

              # Nice alias (so downstream can use `ps.smallworld`).
              smallworld = smallworldWithAllDeps;
            };

          # Add non-uv2nix packages directly as nixpkgs-style python packages.
          extraOverlay =
            pyFinal: pyPrev:
            let
              # --- Patched unicorn (C library + python bindings) ---
              patched-unicorn-src = final.fetchFromGitHub {
                owner = "appleflyerv3";
                repo = "unicorn";
                rev = "mmio_map_pc_sync";
                hash = "sha256-0MH+JS/mPESnTf21EOfGbuVrrrxf1i8WzzwzaPeCt1w=";
              };

              unicornLibPatched = prev.unicorn.overrideAttrs (_: {
                src = patched-unicorn-src;
              });

              unicornPyPatched = pyPrev.unicorn.override {
                unicorn = unicornLibPatched;
              };

              # Your existing builder (see flake's `prebuilts` section)
              mkUnicornafl = final.callPackage ./unicornafl-build { };
            in
            {
              unicorn = unicornPyPatched;

              # Expose these as normal nixpkgs python packages.
              unicornafl = mkUnicornafl pyFinal;

              # pypanda builder comes from the panda-ng flake input.
              pypanda = panda-ng.lib.${system}.pypandaBuilder pyFinal qemu.${system};
            };

          pyOverlay = final.lib.composeExtensions convertedOverlay extraOverlay;
        in
        {
          # Provide a python312 interpreter whose package set includes:
          # - uv2nix-built `smallworld-re` (as `smallworld`)
          # - uv2nix-built `pyghidra`
          # - nixpkgs/custom-built `pypanda`, `unicornafl`, and patched `unicorn`
          python312 =
            let
              # We wrap `withPackages` so the resulting python env derivation
              # contains a setup-hook. This is necessary because setup-hooks
              # on *python packages* (like `ps.smallworld`) are NOT sourced
              # when they are only included inside `python.withPackages`.
              #
              # Nix shells source setup-hooks from *top-level build inputs*,
              # i.e. the python env derivation itself.
              basePython =
                prev.python312.override
                  (old: {
                    self = basePython;
                    packageOverrides = final.lib.composeExtensions
                      (old.packageOverrides or (_: _: { }))
                      pyOverlay;
                  });

              python =
                basePython
                // {
                  withPackages =
                    f:
                    let
                      env = basePython.withPackages f;
                      requested = f basePython.pkgs;
                      needsGhidra =
                        final.lib.any
                          (p:
                            let
                              pname = p.pname or null;
                            in
                            pname == "smallworld-re" || pname == "pyghidra" || pname == "smallworld"
                          )
                          requested;
                    in
                    if needsGhidra then
                      final.buildEnv {
                        name = "${env.name}-smallworld-full";
                        # Tool deps included here so they land on PATH in downstream shells.
                        paths = [
                          env
                          final.jre
                          final.ghidra
                          qemu.${system}
                          final.aflplusplus
                          final.z3
                        ];

                        # Keep the join focused; we mostly need binaries + shell hooks.
                        pathsToLink = [ "/bin" "/nix-support" ];
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
                          export GHIDRA_INSTALL_DIR=${final.ghidra}/lib/ghidra
                          export JAVA_HOME=${final.jre}
                          EOF
                        '';
                      }
                    else
                      env;
                };
            in
            python;

          # Convenience: expose the extended package set directly.
          python312Packages = final.python312.pkgs;
        };

      formatter = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          inherit (pkgs) nixfmt;
        in
        nixfmt
      );
    };
}
