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

    # binaryninja = {
    #   url = "github:jchv/nix-binary-ninja";
    #   inputs.nixpkgs.follows = "nixpkgs";
    # };

    # binjaZip = {
    #   url = "path:./binaryninja_linux_stable_ultimate.zip";
    #   flake = false;
    # };
  };

  outputs =
    inputs@{
      nixpkgs,
      pyproject-nix,
      uv2nix,
      pyproject-build-systems,
      panda-ng,
      nixpkgs-esp-dev,
      ...
    }:
    let
      inherit (nixpkgs) lib;

      binaryninja = inputs.binaryninja or null;
      binjaZip = inputs.binjaZip or null;

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
          python = pkgs.python312; # binja ships with python 3.11
          hacks = pkgs.callPackage pyproject-nix.build.hacks { };
          mkUnicornafl = pkgs.callPackage ./unicornafl-build { };
        in
        {
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
          ]
          ++ lib.optional (bnUltimate.${system} != null) bnUltimate.${system};
          bnPath = lib.optionalString (bnUltimate.${system} != null) "${bnUltimate.${system}}";

          bnPythonPath = lib.optionalString (
            bnUltimate.${system} != null
          ) "${bnUltimate.${system}}/opt/binaryninja/python";

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
            ''
            + lib.optionalString (bnUltimate.${system} != null) ''
              export BINJA_PATH=${bnUltimate.${system}}
              export PYTHONPATH=${bnUltimate.${system}}/opt/binaryninja/python:$PYTHONPATH            '';
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
              export BINJA_PATH=${bnUltimate.${system}}
              export PYTHONPATH=${bnPythonPath}:$PYTHONPATH
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
        in
        {
          inherit printInputsRecursive tests;
          default = pythonSet.smallworld-re;
          venv = virtualenv;
          qemu = qemu.${system};
          binaryninja-ultimate = lib.optionalAttrs (bnUltimate.${system} != null) {
            default = bnUltimate.${system};
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
