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
          oldPanda = panda.packages.${system}.default;
          pandaFixed = oldPanda.overrideAttrs (old: {
            postInstall = old.postInstall + ''
              mkdir -pv $out/lib
              cp $out/bin/libpanda*.so $out/lib/
            '';
          });
        in pandaFixed
      );

    in
    {
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
        in
        {
          default = pkgs.mkShell {
            packages = [
              virtualenv
              pkgs.uv
              pkgs.z3
              pkgs.aflplusplus
              pandaWithLibs.${system}
            ] ++ crossTargetCCs;
            env = {
              UV_NO_SYNC = "1";
              UV_PYTHON = pythonSet.python.interpreter;
              UV_PYTHON_DOWNLOADS = "never";
            };
            shellHook = ''
              unset PYTHONPATH
              export REPO_ROOT=$(git rev-parse --show-toplevel)
            '';
          };
        }
      );

      packages = forAllSystems (system:
        let
          pythonSet = pythonSets.${system};
          pkgs = nixpkgs.legacyPackages.${system};
          virtualenv = virtualEnvProd.${system};
          fixedPanda = pandaWithLibs.${system};
        in
      {
        default = pythonSet.smallworld-re;
        venv = virtualenv;
        panda = fixedPanda;
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
            ];
            pathsToLink = ["/bin" "/etc" "/var"];
          };
          config = {
            Cmd = ["/bin/sh"];
          };
        };
      });
    };
}
