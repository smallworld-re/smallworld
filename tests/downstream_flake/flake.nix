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
      pkgs = import nixpkgs {
        inherit system;
      };

      # mkPython extends a regular nixpkgs Python interpreter with
      # `ps.smallworld`, so downstream projects can keep using
      # `python.withPackages` without importing a global overlay.
      python = smallworld.lib.mkPython { inherit pkgs; };

      pythonEnv = python.withPackages (ps: [
        ps.colorama
        ps.smallworld
      ]);

      # Shared runtime used by both the shell and the runnable test package.
      runtimeInputs = [
        pythonEnv
        pkgs.ghidra
        pkgs.jdk
        pkgs.z3
      ];

      # `nix run .` executes this wrapper, which in turn runs the downstream
      # mkPython integration test with the tools SmallWorld expects on PATH.
      downstreamTest = pkgs.writeShellApplication {
        name = "downstream-flake-test";
        runtimeInputs = runtimeInputs;
        text = ''
          python ${./test.py} "$@"
        '';
      };
    in
    {
      devShells.${system}.default = pkgs.mkShell {
        packages = runtimeInputs;
      };

      packages.${system}.default = downstreamTest;

      apps.${system}.default = {
        type = "app";
        program = "${downstreamTest}/bin/downstream-flake-test";
      };
    };
}
