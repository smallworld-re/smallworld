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

    unicornafl = {
      url = "path:unicornafl-flake";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    panda = {
      url = "github:lluchs/panda/flake";
    };
  };

  outputs =
    {
      nixpkgs,
      pyproject-nix,
      uv2nix,
      pyproject-build-systems,
      unicornafl,
      panda,
      ...
    }:
    let
      inherit (nixpkgs) lib;
      forAllSystems = lib.genAttrs lib.systems.flakeExposed;

      workspace = uv2nix.lib.workspace.loadWorkspace { workspaceRoot = ./.; };
      deps = workspace.deps.all // {
        unicornafl = [];
        pypanda = [];
        colorama = [];
      };

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
          python = pkgs.python312;
          overrides = pkgs.callPackage ./overrides.nix { inherit python; };
          hacks = pkgs.callPackage pyproject-nix.build.hacks {};
          additional = final: prev: {
            unicornafl = hacks.nixpkgsPrebuilt {
              from = (unicornafl.lib.${system}.pythonPackage python.pkgs);
            };
            pypanda = hacks.nixpkgsPrebuilt {
              from = (pypandaBuilder pandaWithLibs.${system}) python.pkgs;
            };
            colorama = hacks.nixpkgsPrebuilt { from = python.pkgs.colorama; };
          };
        in
        (pkgs.callPackage pyproject-nix.build.packages {
          inherit python;
        }).overrideScope
          (
            lib.composeManyExtensions [
              pyproject-build-systems.overlays.wheel
              overlay
              overrides
              additional
            ]
          )
      );

      virtualEnvDev = forAllSystems (
        system:
        let
          pythonSet = pythonSets.${system}.overrideScope editableOverlay;
          venv = pythonSet.mkVirtualEnv "smallworld-re-dev-env" deps;
        in venv
      );

      virtualEnvProd = forAllSystems (
        system:
        let
          pythonSet = pythonSets.${system};
          venv = pythonSet.mkVirtualEnv "smallworld-re-env" deps;
        in venv
      );

      pandaWithLibs = forAllSystems (
        system:
        let
          oldPanda = (panda.packages.${system}.pkgsWithConfig { targetList = ["x86_64-softmmu" "i386-softmmu" "arm-softmmu" "aarch64-softmmu" "ppc-softmmu" "mips-softmmu" "mipsel-softmmu" "mips64-softmmu" "mips64el-softmmu"]; }).panda;
          pkgs = nixpkgs.legacyPackages.${system};
          pandaFixed = pkgs.stdenv.mkDerivation {
            name = oldPanda.name;
            buildInputs = [oldPanda];
            phases = ["installPhase"];
            installPhase = ''
              cp -R ${oldPanda} $out
              chmod -R +w $out
              mkdir -pv $out/lib
              cp $out/bin/*.so $out/lib/
              touch $out/share/panda/mips_bios.bin
              touch $out/share/panda/mipsel_bios.bin
            '';
          };
        in pandaFixed
      );

      pypandaBuilder = pandaPkg: ps: ps.buildPythonPackage {
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
          ps.setuptools_scm
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
            "loongarch64-linux"
          ];
          crossTargetCCs = map (target: pkgs.pkgsCross.${target}.stdenv.cc) crossTargets;
          inputs = [
            pkgs.z3
            pkgs.aflplusplus
            pandaWithLibs.${system}
            pkgs.ghidra
            pkgs.jdk
          ] ++ crossTargetCCs;
          GHIDRA_INSTALL_DIR = "${pkgs.ghidra}/lib/ghidra";
          smallworldBuilt = packages.${system}.default;
        in
        {
          default = pkgs.mkShell {
            packages = [
              virtualenv
              pkgs.uv
            ] ++ inputs;
            env = {
              inherit GHIDRA_INSTALL_DIR;
              UV_NO_SYNC = "1";
              UV_PYTHON = pythonSet.python.interpreter;
              UV_PYTHON_DOWNLOADS = "never";
            };
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
            ] ++ inputs;
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

      packages = forAllSystems (system:
        let
          pythonSet = pythonSets.${system};
          pkgs = nixpkgs.legacyPackages.${system};
          virtualenv = virtualEnvProd.${system};
          upstreamPanda = panda.packages.${system}.default;
          fixedPanda = pandaWithLibs.${system};
        in
      {
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
            pathsToLink = ["/bin" "/etc" "/var"];
          };
          config = {
            Cmd = ["/bin/sh"];
          };
        };
      });

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
