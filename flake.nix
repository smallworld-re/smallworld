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

    panda-ng = {
      url = "github:panda-re/panda-ng";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    nixpkgs-esp-dev = {
      url = "github:mirrexagon/nixpkgs-esp-dev";
      flake = false;
    };

    # binaryninja = {
    #   url = "github:jchv/nix-binary-ninja";
    #   inputs.nixpkgs.follows = "nixpkgs";
    # };

    # binjaZip = {
    #   url = "path:./binaryninja_linux_stable_ultimate.zip";
    #   flake = false;
    # };

    # For building RTOS Demo
    # NOTE: nixpkgs-unstable removed python310, which is
    # required to build zephyr. So we pin nixpkgs to 25.11
    # when building our RTOS Demo binary.
    nixpkgs-25-11.url = "github:nixos/nixpkgs/nixos-25.11";
    zephyr-nix = {
      url = "github:adisbladis/zephyr-nix";
      inputs.nixpkgs.follows = "nixpkgs-25-11";
    };
    west2nix = {
      url = "github:adisbladis/west2nix";
      inputs.nixpkgs.follows = "nixpkgs-25-11";
      inputs.zephyr-nix.follows = "zephyr-nix";
    };
  };

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
      systems = lib.systems.flakeExposed;
      forAllSystems = lib.genAttrs systems;

      binaryninja = inputs.binaryninja or null;
      binjaZip = inputs.binjaZip or null;

      ghidraInstallDir = ghidra: "${ghidra}/lib/ghidra";

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

      overlay = workspace.mkPyprojectOverlay { sourcePreference = "wheel"; };

      # Parse pyproject.toml to access dependency groups natively
      project = pyproject-nix.lib.project.loadPyproject {
        projectRoot = ./.;
      };

      perSystem = forAllSystems (
        system:
        let
          basePkgs = nixpkgs.legacyPackages.${system};
          basePython = basePkgs.python312;
          qemu = panda-ng.packages.${system}.qemu;

          # 2. Prebuilt & uv2nix structures
          pythonNativeAddons =
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
            };

          prebuilts =
            _final: _prev:
            let
              hacks = basePkgs.callPackage pyproject-nix.build.hacks { };
              native = pythonNativeAddons {
                pythonPkgs = basePython.pkgs;
                unicornPy = basePython.pkgs.unicorn;
              } basePkgs;
            in
            {
              unicorn = hacks.nixpkgsPrebuilt {
                from = native.unicorn;
              };

              unicornafl = hacks.nixpkgsPrebuilt {
                from = native.unicornafl;
              };

              pypanda = hacks.nixpkgsPrebuilt {
                from = native.pypanda;
              };

              colorama = hacks.nixpkgsPrebuilt {
                from = basePython.pkgs.colorama;
              };
            };

          pythonSet =
            let
              overrides = basePkgs.callPackage ./overrides.nix { python = basePython; };
              pyprojectPkgs = basePkgs.callPackage pyproject-nix.build.packages { python = basePython; };
            in
            pyprojectPkgs.overrideScope (
              lib.composeManyExtensions [
                pyproject-build-systems.overlays.wheel
                overlay
                overrides
                prebuilts
              ]
            );

          bnUltimate =
            if binaryninja != null && binjaZip != null then
              let
                bnPkgs = binaryninja.packages.${system};
              in
              bnPkgs.binary-ninja-ultimate-wayland.override { overrideSource = binjaZip; }
            else
              null;

          # 3. Final Pkgs instantiation with our completed overlay injected
          pkgs = import nixpkgs {
            inherit system;
            overlays = [ self.overlays.default ];
            config.allowUnfree = true;
          };

          toolInputs = [
            pkgs.z3
            pkgs.aflplusplus
            qemu
            pkgs.ghidra
            pkgs.jdk
          ]
          ++ lib.optional (bnUltimate != null) bnUltimate;

          bnPythonPath = lib.optionalString (
            bnUltimate != null
          ) "${bnUltimate}/opt/binaryninja/python";

          GHIDRA_INSTALL_DIR = ghidraInstallDir pkgs.ghidra;

          # Dynamically map the dev dependencies from pyproject.toml to standard python packages
          devDeps = project.dependencyGroups.dev or [];
          resolvePsDep = ps: dep:
            let
              name = dep.name;
              nixName = builtins.replaceStrings ["-"] ["_"] name;
              lowerNixName = lib.toLower nixName;
            in
              if ps ? ${name} then ps.${name}
              else if ps ? ${nixName} then ps.${nixName}
              else if ps ? ${lowerNixName} then ps.${lowerNixName}
              else null;

          pythonEnvDev = pkgs.python312.withPackages (ps: 
            let
              resolvedDev = builtins.filter (x: x != null) (builtins.map (resolvePsDep ps) devDeps);
            in [ ps.smallworld-re ] ++ resolvedDev
          );

          pythonEnvProd = pkgs.python312.withPackages (ps: [ ps.smallworld-re ]);

        in
        {
          inherit
            basePkgs
            pkgs
            basePython
            qemu
            pythonNativeAddons
            prebuilts
            pythonSet
            pythonEnvDev
            pythonEnvProd
            bnUltimate
            toolInputs
            bnPythonPath
            GHIDRA_INSTALL_DIR;
        }
      );

    in
    rec {
      overlays.default =
        final: prev:
        let
          system = final.stdenv.hostPlatform.system;
          sys = perSystem.${system};

          toolDeps = [
            sys.qemu
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
            pyFinal.angr
          ];

          hacks = final.callPackage pyproject-nix.build.hacks { };

          basePyOverlay = hacks.toNixpkgs {
            pythonSet = sys.pythonSet;
            packages = [
              "smallworld-re"
              "pyghidra"
              "pypcode"
              "angr"
              "pyvex"
              "cle"
              "archinfo"
              "ailment"
              "claripy"
              "pyxdia"
              "uefi-firmware"
            ];
          };

          convertedOverlay =
            pyFinal: pyPrev:
            let
              converted = basePyOverlay pyFinal pyPrev;
              angrFixed = converted.angr.overridePythonAttrs (old: {
                postFixup = (old.postFixup or "") + ''
                  addAutoPatchelfSearchPath ${pyFinal.pyvex}
                '';
              });
              smallworldWithAllDeps = (converted."smallworld-re").overridePythonAttrs (old: {
                propagatedBuildInputs =
                  (old.propagatedBuildInputs or [ ]) ++ ((pythonAddonDepsFor pyFinal) ++ pkgToolDeps);
              });
            in
            converted
            // {
              angr = angrFixed;
              "smallworld-re" = smallworldWithAllDeps;
              smallworld = smallworldWithAllDeps;
            };

          extraOverlay =
            pyFinal: pyPrev:
            let
              native = sys.pythonNativeAddons {
                pythonPkgs = pyFinal;
                unicornPy = pyPrev.unicorn;
              } (final // { inherit (prev) unicorn; });
            in
            {
              inherit (native) unicorn unicornafl pypanda;
            };

          pyOverlay = final.lib.composeExtensions convertedOverlay extraOverlay;

        in
        {
          python312 =
            let
              basePython = prev.python312.override (old: {
                self = basePython;
                packageOverrides = final.lib.composeExtensions (old.packageOverrides or (_: _: { })) pyOverlay;
              });

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
                      paths = [ env ] ++ envToolDeps;
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

      pythonSet = forAllSystems (system: perSystem.${system}.pythonSet);
      pythonDeps = deps;
      prebuilts = forAllSystems (system: perSystem.${system}.prebuilts);

      formatter = forAllSystems (system: (perSystem.${system}.basePkgs).nixfmt-rfc-style);

      devShells = forAllSystems (
        system:
        let
          sys = perSystem.${system};
          pkgs = sys.pkgs;
          smallworldBuilt = packages.${system}.default;
        in
        {
          pythonEnv = pkgs.mkShell {
            packages = [ sys.pythonEnvProd ];
          };

          default = pkgs.mkShell {
            packages = [
              sys.pythonEnvDev
              pkgs.uv
              pkgs.nixfmt-rfc-style
              pkgs.nixfmt-tree
            ]
            ++ sys.toolInputs;

            env = {
              GHIDRA_INSTALL_DIR = sys.GHIDRA_INSTALL_DIR;
              UV_NO_SYNC = "1";
              UV_PYTHON = "${sys.pythonEnvDev}/bin/python";
              UV_PYTHON_DOWNLOADS = "never";
            };

            hardeningDisable = [ "all" ];

            shellHook = ''
              unset PYTHONPATH
              export REPO_ROOT=$(git rev-parse --show-toplevel)
            ''
            + lib.optionalString (sys.bnUltimate != null) ''
              export BINJA_PATH=${sys.bnUltimate}
              export PYTHONPATH=${sys.bnUltimate}/opt/binaryninja/python:$PYTHONPATH
            '';
          };

          imperative = pkgs.mkShell {
            packages = [
              pkgs.python312
              pkgs.python312Packages.pip
              pkgs.python312Packages.setuptools
            ]
            ++ sys.toolInputs;

            env = {
              GHIDRA_INSTALL_DIR = sys.GHIDRA_INSTALL_DIR;
            };

            shellHook = ''
              export PYTHONPATH="${smallworldBuilt}/${pkgs.python312.sitePackages}:$PYTHONPATH"
              unset SOURCE_DATE_EPOCH
            ''
            + lib.optionalString (sys.bnUltimate != null) ''
              export BINJA_PATH=${sys.bnUltimate}
              export PYTHONPATH=${sys.bnPythonPath}:$PYTHONPATH
            '';
          };
        }
      );

      packages = forAllSystems (
        system:
        let
          sys = perSystem.${system};
          pkgs = sys.pkgs;

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
        in
        {
          inherit printInputsRecursive tests rtos_demo;

          default = sys.pkgs.python312Packages.smallworld-re;
          env = sys.pythonEnvProd;
          qemu = sys.qemu;
          binaryninja-ultimate = lib.optionalAttrs (sys.bnUltimate != null) {
            default = sys.bnUltimate;
          };
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
                sys.qemu
                sys.pythonEnvProd
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
    };
}
