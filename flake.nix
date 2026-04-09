# Nix flake for smallworld-re.
#
# Reader's guide:
# - this file is intentionally small and mostly declarative
# - `nix/python-packages.nix` turns `uv.lock` into Nix Python packages
# - `nix/runtime-support.nix` assembles shells, runtime envs, and downstream helpers
# - `nix/panda-packages.nix` contains the PANDA-specific native build glue
#
# If you are new to Nix, the most important idea is:
# "inputs" says what external code we depend on, and "outputs" says what
# commands like `nix build` and `nix develop` expose to users.
{
  description = "smallworld-re";

  # External inputs. `follows` means "reuse the parent's copy" so we do not
  # accidentally pull in multiple versions of the same dependency tree.
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

    # PANDA is the only major dependency that still needs custom Nix glue.
    # See `nix/panda-packages.nix` for the explanation.
    panda-ng = {
      url = "github:panda-re/panda-ng";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    # Optional Binary Ninja support (uncomment both to enable).
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
      panda-ng,
      pyproject-nix,
      pyproject-build-systems,
      uv2nix,
      ...
    }:
    let
      lib = nixpkgs.lib;
      supportedSystems = lib.systems.flakeExposed;
      forEachSystem = lib.genAttrs supportedSystems;

      pkgsFor = system: nixpkgs.legacyPackages.${system};
      pythonFor = system: (pkgsFor system).python312;

      pandaPackages = import ./nix/panda-packages.nix {
        inherit
          lib
          forEachSystem
          panda-ng
          pkgsFor
          ;
      };

      pythonPackages = import ./nix/python-packages.nix {
        inherit
          lib
          forEachSystem
          pkgsFor
          pyproject-nix
          pyproject-build-systems
          pythonFor
          uv2nix
          ;
        pandaNgPackages = pandaPackages;
      };

      runtimeSupport = import ./nix/runtime-support.nix {
        inherit
          inputs
          lib
          pkgsFor
          pythonFor
          ;
        inherit (pythonPackages)
          devSelection
          mkLockedVirtualenv
          mkPythonSet
          mkSmallworldPythonModule
          pythonSets
          runtimeSelection
          ;
      };
    in
    {
      devShells = forEachSystem (system: {
        default = runtimeSupport.mkDeveloperShell system;
      });

      packages = forEachSystem runtimeSupport.mkPackageOutputs;

      # Small helper library for downstream flakes.
      lib = {
        mkPython = runtimeSupport.mkDownstreamPython;
        mkPythonShell = runtimeSupport.mkDownstreamPythonShell;
      };

      formatter = forEachSystem (system: (pkgsFor system).nixfmt);
    };
}
