{
  inputs.nixpkgs.url = "github:nixos/nixpkgs";

  outputs = { nixpkgs, ... }:
    let
      system = "x86_64-darwin";
      pkgs = import nixpkgs { inherit system; };
    in
    {
      devShells.${system}.default = pkgs.mkShell {
        packages = [ pkgs.nasm pkgs.gnumake pkgs.unixtools.xxd pkgs.capstone];
      };
    };
}