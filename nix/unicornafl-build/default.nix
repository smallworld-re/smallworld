# Repo-local packaging for the `unicornafl` Python binding used by SmallWorld.
#
# This lives under `nix/` with the rest of the flake implementation because it
# is part of the Python/native packaging graph, not a standalone project.
{
  lib,
  fetchFromGitHub,
  rustPlatform,
  cargo,
  rustc,
  cmake,
  pkg-config,
  stdenv,
  unicornLibraryPath ? null,
}:
let
  src = fetchFromGitHub {
    owner = "AFLplusplus";
    repo = "unicornafl";
    rev = "7b79cd88c61efc1cddef89406aee2fe25ff83d54"; # from aflpp submodule at tagged version v4.34c
    hash = "sha256-zRsgBLlWeLK9pNI3h9M+JH0d5hDQyb+4r1GKrodD9Bc=";
    postFetch = ''
      cp ${./Cargo.lock} $out/Cargo.lock
      sed -i 's/^compatibility/# compatibility/g' $out/pyproject.toml
    '';
  };
  cargoToml = builtins.fromTOML (builtins.readFile "${src}/Cargo.toml");
  projectName = cargoToml.package.name;
  projectVersion = cargoToml.package.version;
in
ps:
ps.buildPythonPackage {
  pname = projectName;
  version = projectVersion;
  src = src;
  pyproject = true;
  cargoDeps = rustPlatform.fetchCargoVendor {
    inherit src;
    hash = "sha256-/JSFvKFNRLluVjd74MpJ9yappQMv7hYMsBjlqDjRedY=";
  };
  dontUseCmakeConfigure = true;
  propagatedBuildInputs = [
    ps.unicorn
  ];
  nativeBuildInputs = [
    rustPlatform.cargoSetupHook
    rustPlatform.maturinBuildHook
    rustPlatform.bindgenHook
    cargo
    rustc
    cmake
    pkg-config
  ];
  postFixup = lib.optionalString (stdenv.hostPlatform.isDarwin && unicornLibraryPath != null) ''
    while IFS= read -r extension; do
      install_name_tool -add_rpath "${unicornLibraryPath}" "$extension"
    done < <(find "$out" -type f -name 'unicornafl*.so')
  '';
}
