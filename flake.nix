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
      url = "path:unicornafl";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    # panda = {
    #   url = "github:panda-re/panda/v1.8.57";
    # };
  };

  outputs =
    {
      nixpkgs,
      pyproject-nix,
      uv2nix,
      pyproject-build-systems,
      unicornafl,
      # panda,
      ...
    }:
    let
      inherit (nixpkgs) lib;
      forAllSystems = lib.genAttrs lib.systems.flakeExposed;

      workspace = uv2nix.lib.workspace.loadWorkspace { workspaceRoot = ./.; };

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
              from = unicornafl.packages.${system}.default;
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

    in
    {
      devShells = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          pythonSet = pythonSets.${system}.overrideScope editableOverlay;
          virtualenv = pythonSet.mkVirtualEnv "smallworld-re-dev-env" (workspace.deps.all // {
            unicornafl = [];
          });
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
              # (panda.packages.${system}.default.overrideAttrs (old:
              # let
              #   oldDeps = panda.packages.x86_64-linux.default.buildInputs;
              #   filtered = builtins.filter (p: p.name != "libosi") oldDeps;
              # in
              # {
              #   buildInputs = filtered;
              # }))
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
          pythonSet = pythonSets.${system}.overrideScope editableOverlay;
          pkgs = nixpkgs.legacyPackages.${system};
        in
      rec {
        default = {
          venv = pythonSet.mkVirtualEnv "smallworld-re-env" workspace.deps.default;
          package = pythonSet.smallworld-re;
        };
        dockerImage = pkgs.dockerTools.buildImage {
          name = "smallworld-re";
          config = {
            Cmd = ["${default.venv}/bin/python3"];
          };
        };
      });
    };
}
