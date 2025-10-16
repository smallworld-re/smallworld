{
  description = "unicornafl";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    crane = {
      url = "github:ipetkov/crane";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
      ...
    }@inputs:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ inputs.rust-overlay.overlays.default ];
        };

        src = pkgs.fetchFromGitHub {
          owner = "AFLplusplus";
          repo = "unicornafl";
          rev = "7b79cd88c61efc1cddef89406aee2fe25ff83d54"; # from aflpp submodule at tagged version v4.34c
          hash = "sha256-s6ksuSLIk+O1OVnmLpX66VuRGC9YhBIIT8I225mmrZg=";
          postFetch = ''
            cp ${./Cargo.lock} $out/Cargo.lock
            sed -i 's/^compatibility/# compatibility/g' $out/pyproject.toml
          '';
        };
        # Get a custom rust toolchain
        customRustToolchain = pkgs.rust-bin.stable.latest.default;
        craneLib =
          (inputs.crane.mkLib pkgs).overrideToolchain customRustToolchain;

        projectName =
          (craneLib.crateNameFromCargoToml { cargoToml = "${src}/Cargo.toml"; }).pname;
        projectVersion = (craneLib.crateNameFromCargoToml {
          cargoToml = "${src}/Cargo.toml";
        }).version;

        pythonVersion = pkgs.python312;
        wheelTail = "cp38-abi3-linux_x86_64";
        wheelName = "${projectName}-${projectVersion}-${wheelTail}.whl";

        crateCfg = {
          src = craneLib.cleanCargoSource src;
          # cargoVendorDir = craneLib.vendorCargoDeps { cargoLock = ./Cargo.lock; };
          nativeBuildInputs = [ pythonVersion pkgs.rustPlatform.bindgenHook pkgs.cmake pkgs.pkg-config ];
        };
        # Build the library, then re-use the target dir to generate the wheel file with maturin
        crateWheel = (craneLib.buildPackage (crateCfg // {
          pname = projectName;
          version = projectVersion;
        })).overrideAttrs (old: {
          nativeBuildInputs = old.nativeBuildInputs ++ [ pkgs.maturin ];
          buildPhase = old.buildPhase + ''
            maturin build --release --target-dir ./target
          '';
          installPhase = old.installPhase + ''
            cp target/wheels/${wheelName} $out/
          '';
        });
      in
      rec {
        packages = {
          # default = crateWheel; # The wheel itself

          # A python version with the library installed
          pythonEnv = pythonVersion.withPackages
            (ps: [ (lib.pythonPackage ps) ] ++ (with ps; [ ipython ]));

          default = pkgs.python3Packages.buildPythonPackage {
              pname = projectName;
              format = "wheel";
              version = projectVersion;
              src = "${crateWheel}/${wheelName}";
              doCheck = false;
              pythonImportsCheck = [ projectName ];
          };
        };

        lib = {
          # To use in other builds with the "withPackages" call
          pythonPackage = ps:
            ps.buildPythonPackage {
              pname = projectName;
              format = "wheel";
              version = projectVersion;
              src = "${crateWheel}/${wheelName}";
              doCheck = false;
              pythonImportsCheck = [ projectName ];
            };
        };

        devShells = rec {
          rust = pkgs.mkShell {
            name = "rust-env";
            src = ./.;
            nativeBuildInputs = with pkgs; [ pkg-config rust-analyzer maturin ];
          };
          python = pkgs.mkShell {
            name = "python-env";
            src = ./.;
            nativeBuildInputs = [ packages.pythonEnv ];
          };
          default = rust;
        };
      }
    );
}
