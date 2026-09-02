# Repo-local packaging for the `styxafl` Python wheel: a thin PyO3 bridge that
# couples the styx-emulator Rust crate with the AFL++ forkserver protocol so
# SmallWorld's `Machine.fuzz_with_styx(...)` has the same shape as the existing
# AFL-via-unicornafl path.
#
# Mirrors nix/styx-emulator-build but consumes the in-repo source at
# `nix/styxafl-src/` instead of fetching from GitHub.
{
  lib,
  rustPlatform,
  cargo,
  rustc,
  cmake,
  pkg-config,
  protobuf,
  stdenv,
}:
let
  src = ../styxafl-src;
  cargoToml = builtins.fromTOML (builtins.readFile (src + "/Cargo.toml"));
  projectName = cargoToml.package.name;
  projectVersion = cargoToml.package.version;
in
ps:
ps.buildPythonPackage {
  pname = projectName;
  version = projectVersion;
  inherit src;
  pyproject = true;

  cargoDeps = rustPlatform.fetchCargoVendor {
    inherit src;
    hash = "sha256-v1d8rN4djahXiHmInYSAb7cm2eBu47jhpCC5amMoWrU=";
  };

  dontUseCmakeConfigure = true;

  nativeBuildInputs = [
    rustPlatform.cargoSetupHook
    rustPlatform.maturinBuildHook
    rustPlatform.bindgenHook
    cargo
    rustc
    cmake
    pkg-config
    protobuf
  ];

  PROTOC = "${protobuf}/bin/protoc";
  PROTOC_INCLUDE = "${protobuf}/include";
}
