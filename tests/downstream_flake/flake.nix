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
      systems = lib.systems.flakeExposed;
      forAllSystems = lib.genAttrs systems;

      mkOutputs =
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

          pythonEnv = python.withPackages (
            ps:
            [
              ps.smallworld
              ps.coverage
            ]
            ++ pythonExtras ps
          );

          # The runnable test package only needs the mkPython env. When Ghidra
          # support is enabled, `mkPython` already carries the matching native
          # runtime tools and environment variables.
          runtimeInputs = [ pythonEnv ];

          # `nix run .` executes this wrapper, which in turn runs the downstream
          # mkPython integration test with the tools SmallWorld expects on PATH.
          downstreamTest = pkgs.writeShellApplication {
            name = "downstream-flake-test";
            runtimeInputs = runtimeInputs;
            text = ''
              if [ "''${SMALLWORLD_COVERAGE:-}" = "1" ]; then
                if [ -n "''${SMALLWORLD_COVERAGE_RCFILE:-}" ]; then
                  exec python -m coverage run --parallel-mode --rcfile "''${SMALLWORLD_COVERAGE_RCFILE}" ${./test.py} "$@"
                fi
                exec python -m coverage run --parallel-mode ${./test.py} "$@"
              fi
              exec python ${./test.py} "$@"
            '';
          };
        in
        {
          devShells.default = smallworld.lib.mkPythonShell {
            inherit pkgs;
            extraPythonPackages = pythonExtras;
          };

          packages.default = downstreamTest;

          apps.default = {
            type = "app";
            program = "${downstreamTest}/bin/downstream-flake-test";
          };
        };
    in
    {
      devShells = forAllSystems (system: (mkOutputs system).devShells);
      packages = forAllSystems (system: (mkOutputs system).packages);
      apps = forAllSystems (system: (mkOutputs system).apps);
    };
}
