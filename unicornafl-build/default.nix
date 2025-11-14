{
  fetchFromGitHub,
  rustPlatform,
  cargo,
  rustc,
  cmake,
  pkg-config,
}:
let
  src = fetchFromGitHub {
    owner = "AFLplusplus";
    repo = "unicornafl";
    rev = "7b79cd88c61efc1cddef89406aee2fe25ff83d54"; # from aflpp submodule at tagged version v4.34c
    hash = "sha256-s6ksuSLIk+O1OVnmLpX66VuRGC9YhBIIT8I225mmrZg=";
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
    hash = "sha256-8l29KYpyljnBsdbpuRh/7BhsBM1cIBIWI8Uno1F/kTg=";
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
}
