{
  description = "Test Flake";

  inputs = {
    smallworld = {
      url = "../..";
    };
    nixpkgs.follows = "smallworld/nixpkgs";
  };

  outputs =
    {
      nixpkgs,
      smallworld,
      ...
    }:
    let
      system = "x86_64-linux"; # change if needed (e.g. aarch64-darwin)

      pkgs = nixpkgs.legacyPackages.${system}.extend smallworld.overlays.default;

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
