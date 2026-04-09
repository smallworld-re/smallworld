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
      lib = nixpkgs.lib;
      supportedSystems = [
        "x86_64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];
      forAllSystems = lib.genAttrs supportedSystems;

      perSystem = forAllSystems (
        system:
        let
          pkgs = import nixpkgs {
            inherit system;
          };

          # mkPython extends a regular nixpkgs Python interpreter with
          # `ps.smallworld`, so downstream projects can keep using
          # `python.withPackages` without importing a global overlay.
          python = smallworld.lib.mkPython { inherit pkgs; };
          pythonExtras = ps: [ ps.colorama ];

          pythonEnv = python.withPackages (ps: [ ps.smallworld ] ++ pythonExtras ps);

          # `nix run .` executes this wrapper, which in turn runs the downstream
          # mkPython integration test. The mkPython environment already carries
          # the native Ghidra toolchain it needs on PATH.
          downstreamTest = pkgs.writeShellApplication {
            name = "downstream-flake-test";
            runtimeInputs = [ pythonEnv ];
            text = ''
              python ${./test.py} "$@"
            '';
          };
        in
        {
          devShell = smallworld.lib.mkPythonShell {
            inherit pkgs;
            extraPythonPackages = pythonExtras;
          };

          package = downstreamTest;

          app = {
            type = "app";
            program = "${downstreamTest}/bin/downstream-flake-test";
          };
        }
      );
    in
    {
      devShells = lib.mapAttrs (_: value: { default = value.devShell; }) perSystem;

      packages = lib.mapAttrs (_: value: { default = value.package; }) perSystem;

      apps = lib.mapAttrs (_: value: { default = value.app; }) perSystem;
    };
}
