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
      pythonExtras = ps: [ ps.colorama ];

      pythonEnv = python.withPackages (ps: [ ps.smallworld ] ++ pythonExtras ps);

      # The runnable test package only needs the mkPython env plus the native
      # Ghidra toolchain. z3 already comes from the Python environment.
      runtimeInputs = [
        pythonEnv
        pkgs.ghidra
        pkgs.jdk
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
      devShells.${system}.default = smallworld.lib.mkPythonShell {
        inherit pkgs;
        extraPythonPackages = pythonExtras;
      };

      packages.${system}.default = downstreamTest;

      apps.${system}.default = {
        type = "app";
        program = "${downstreamTest}/bin/downstream-flake-test";
      };
    };
}
