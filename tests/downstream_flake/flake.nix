{
  description = "Test Flake";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    smallworld = {
      url = "../..";
      inputs.nixpkgs.follows = "nixpkgs";
    };

  };

  outputs =
    {
      self,
      nixpkgs,
      smallworld,
    }:
    let
      system = "x86_64-linux"; # change if needed (e.g. aarch64-darwin)

      pkgs = import nixpkgs {
        inherit system;
        overlays = [ smallworld.overlays.default ];
      };

      python = pkgs.python312;
      pythonEnv = python.withPackages (ps: [
        ps.smallworld
      ]);
    in
    {
      devShells.${system}.default = pkgs.mkShell {
        packages = [
          pythonEnv
        ];
      };
    };
}
