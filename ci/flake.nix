# CI-only flake for smallworld-re.
#
# The main flake exposes the package and developer shell that downstream users
# should consume. This separate flake keeps heavyweight test/demo toolchains
# out of that public interface.
{
  description = "smallworld-re CI outputs";

  inputs = {
    smallworld.url = "..";
    nixpkgs.follows = "smallworld/nixpkgs";

    # Xtensa cross-compiler used to build some test binaries.
    nixpkgs-esp-dev = {
      url = "github:mirrexagon/nixpkgs-esp-dev";
      flake = false;
    };

    # Zephyr tooling only needed for the RTOS demo artifact.
    zephyr-nix = {
      url = "github:adisbladis/zephyr-nix";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.pyproject-nix.follows = "smallworld/pyproject-nix";
    };
    west2nix = {
      url = "github:adisbladis/west2nix";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.zephyr-nix.follows = "zephyr-nix";
    };
  };

  outputs =
    {
      nixpkgs,
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
    in
    {
      packages = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;

          xtensaGcc = pkgs.callPackage "${nixpkgs-esp-dev}/pkgs/esp8266/gcc-xtensa-lx106-elf-bin.nix" { };

          tests = pkgs.callPackage ../tests {
            inherit xtensaGcc;
            x86_64_glibc_path = pkgs.glibc.outPath;
          };

          rtos_demo = pkgs.callPackage ../use_cases/rtos_demo {
            zephyr = zephyr-nix.packages.${system};
            west2nix = pkgs.callPackage west2nix.lib.mkWest2nix { };
          };
        in
        {
          inherit tests rtos_demo;
        }
      );
    };
}
