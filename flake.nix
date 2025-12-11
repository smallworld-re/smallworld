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

    pandaPkgs = {
      url = "github:nixos/nixpkgs?rev=911ad1e67f458b6bcf0278fa85e33bb9924fed7e";
    };

    panda = {
      url = "github:lluchs/panda/flake";
      inputs.nixpkgs.follows = "pandaPkgs";
    };
  };

  outputs =
    {
      nixpkgs,
      pyproject-nix,
      uv2nix,
      pyproject-build-systems,
      panda,
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
        in
        {
          unicornafl = hacks.nixpkgsPrebuilt {
            from = (mkUnicornafl python.pkgs);
          };
          pypanda = hacks.nixpkgsPrebuilt {
            from = (pypandaBuilder pandaWithLibs.${system}) python.pkgs;
          };
          colorama = hacks.nixpkgsPrebuilt { from = python.pkgs.colorama; };
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

      pandaWithLibs = forAllSystems (
        system:
        let
          oldPanda =
            (panda.packages.${system}.pkgsWithConfig {
              targetList = [
                "x86_64-softmmu"
                "i386-softmmu"
                "arm-softmmu"
                "aarch64-softmmu"
                "ppc-softmmu"
                "mips-softmmu"
                "mipsel-softmmu"
                "mips64-softmmu"
                "mips64el-softmmu"
              ];
            }).panda;
          pkgs = nixpkgs.legacyPackages.${system};
          pandaFixed = pkgs.stdenv.mkDerivation {
            name = oldPanda.name;
            buildInputs = [ oldPanda ];
            phases = [ "installPhase" ];
            installPhase = ''
              cp -R ${oldPanda} $out
              chmod -R +w $out
              mkdir -pv $out/lib
              cp $out/bin/*.so $out/lib/
              touch $out/share/panda/mips_bios.bin
              touch $out/share/panda/mipsel_bios.bin
            '';
          };
        in
        pandaFixed
      );

      pypandaBuilder =
        pandaPkg: ps:
        ps.buildPythonPackage {
          pname = "pandare";
          version = "1.8";
          format = "setuptools";
          src = "${panda}/panda/python/core";

          propagatedBuildInputs = with ps; [
            cffi
            protobuf
            colorama
          ];

          nativeBuildInputs = [
            ps.setuptools-scm
          ];

          buildInputs = [ pandaPkg ];

          postPatch = ''
            substituteInPlace setup.py \
              --replace 'install_requires=parse_requirements("requirements.txt"),' ""
            substituteInPlace pandare/utils.py \
              --replace '/usr/local/bin/' '${pandaPkg}'
            substituteInPlace pandare/panda.py \
              --replace 'self.plugin_path = plugin_path' "self.plugin_path = plugin_path or pjoin('${pandaPkg}', 'lib/panda', arch)" \
              --replace 'if libpanda_path:' 'if True:' \
              --replace '= libpanda_path' "= libpanda_path or pjoin('${pandaPkg}', 'bin', f'libpanda-{arch}.so')" \
              --replace 'realpath(pjoin(self.get_build_dir(), "pc-bios"))' "pjoin('${pandaPkg}', 'share/panda')"

            # Use auto-generated files from separate derivation above.
            rm create_panda_datatypes.py
            rm -r pandare/{include,autogen}
            cp -rt pandare "${pandaPkg}"/lib/panda/python/{include,autogen,plog_pb2.py}
          '';
        };
    in
    rec {
      devShells = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          pythonSet = pythonSets.${system}.overrideScope editableOverlay;
          virtualenv = virtualEnvDev.${system};
          crossTargets = [
            "aarch64-multiplatform"
            # "arm-embedded"
            # "armhf-embedded"
            # "mips-linux-gnu"
            # "mipsel-linux-gnu"
            # "mips64-linux-gnuabi64"
            # "mips64el-linux-gnuabi64"
            # "riscv64"
            # "ppc64"
            # "loongarch64-linux"
          ];
          crossTargetCCs = map (target: pkgs.pkgsCross.${target}.stdenv.cc) crossTargets;
          inputs = [
            pkgs.z3
            pkgs.aflplusplus
            pandaWithLibs.${system}
            pkgs.ghidra
            pkgs.jdk
            pkgs.stdenv.cc
            # pkgs.nasm
          ]
          ++ crossTargetCCs;
          GHIDRA_INSTALL_DIR = "${pkgs.ghidra}/lib/ghidra";
          smallworldBuilt = packages.${system}.default;
        in
        {
          default = pkgs.mkShell {
            packages = [
              virtualenv
              pkgs.uv
              pkgs.nixfmt-rfc-style
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
          upstreamPanda = panda.packages.${system}.default;
          fixedPanda = pandaWithLibs.${system};

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
        in
        {
          inherit printInputsRecursive;
          default = pythonSet.smallworld-re;
          venv = virtualenv;
          panda = fixedPanda;
          upstreamPanda = upstreamPanda;
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
                fixedPanda
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
          inherit (pkgs) nixfmt-rfc-style;
        in
        nixfmt-rfc-style
      );
    };
}
