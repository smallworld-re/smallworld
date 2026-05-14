# Repo-local packaging for the `styx_emulator` Python wheel used by SmallWorld's
# Styx backend.
#
# Source layout: styx-emulator is a polyglot Rust monorepo. The Python wheel
# lives inside a *separate* sub-workspace at `styx/bindings/`, which has its
# own `Cargo.toml` + `Cargo.lock` and lists `styx-py-api` as a member. We pin
# that sub-workspace's lockfile here next to `default.nix`.
#
# After the first successful build any reproducibility-tuning happens by
# updating the two hashes below.
{
  lib,
  fetchFromGitHub,
  rustPlatform,
  cargo,
  rustc,
  cmake,
  pkg-config,
  protobuf,
  stdenv,
}:
let
  src = fetchFromGitHub {
    owner = "styx-emulator";
    repo = "styx-emulator";
    rev = "71a7746fe192a56b257549842cc3ec55ffc8f75a";
    hash = "sha256-OfIpb/gb28LclLtHmIlSyVOu0gyU9vnnJwKrIyb+xYw=";
  };
  bindingsWorkspaceToml = builtins.fromTOML (
    builtins.readFile "${src}/styx/bindings/Cargo.toml"
  );
  projectVersion = bindingsWorkspaceToml.workspace.package.version;
in
ps:
ps.buildPythonPackage {
  pname = "styx-emulator";
  version = projectVersion;
  inherit src;
  # Where pyproject.toml lives; maturin starts here, walks up to find the
  # bindings workspace Cargo.toml.
  sourceRoot = "${src.name}/styx/bindings/styx-py-api";
  pyproject = true;

  cargoDeps = rustPlatform.fetchCargoVendor {
    inherit src;
    # Resolve relative to the sub-workspace root and inject the pinned
    # Cargo.lock that ships next to this file (since the styx-emulator repo
    # ships its bindings workspace with a transient lockfile we want to pin).
    sourceRoot = "${src.name}/styx/bindings";
    cargoLockOverride = ./Cargo.lock;
    hash = "sha256-IUNbjYpgjkFUjeQckiFfJt3OCH9tw4pc/KOnsSU2OZA=";
  };

  # Inject our pinned Cargo.lock into the unpacked source tree. cargoSetupHook
  # validates the lockfile lives at sourceRoot, and the bindings sub-workspace
  # also expects one at `styx/bindings/`. We also need the whole tree writable
  # because styx-sla's build script copies/patches files inside the source
  # checkout under OUT_DIR but resolves some paths relative to the crate root.
  #
  # Additionally pyo3-stub-gen's build.rs forks `cargo metadata`, which walks
  # up the directory tree looking for `.cargo/config.toml`. nixpkgs's
  # cargoSetupHook leaves an unsubstituted `@vendor@` template inside the
  # copied vendor directory itself; that file is found first by the inner
  # cargo invocation and breaks the build. Substitute it post-hoc so the
  # inner cargo agrees with the outer build.
  postUnpack = ''
    chmod -R u+w source
    install -m 0644 ${./Cargo.lock} source/styx/bindings/Cargo.lock
    install -m 0644 ${./Cargo.lock} source/styx/bindings/styx-py-api/Cargo.lock
  '';

  postPatch = ''
    if [ -f "$cargoDepsCopy/.cargo/config.toml" ]; then
      substituteInPlace "$cargoDepsCopy/.cargo/config.toml" \
        --replace-quiet "@vendor@" "$cargoDepsCopy"
    fi
    # pyo3-stub-gen 0.9.1's build script forks `cargo metadata --all-features`
    # purely to decide whether to set `cfg(pyo3_0_25)`. That metadata call
    # fails in nix offline builds because the inner cargo lookup tries to
    # resolve dev-dependencies (e.g. `test-case`) that the outer vendoring
    # doesn't include. We pin pyo3 0.25 in the styx workspace anyway, so
    # replace the build script with a stub that always emits the cfg.
    stub_build="$cargoDepsCopy/source-registry-0/pyo3-stub-gen-0.9.1/build.rs"
    if [ -f "$stub_build" ]; then
      cat > "$stub_build" <<'STUB_EOF'
fn main() {
    pyo3_build_config::use_pyo3_cfgs();
    println!("cargo::rustc-check-cfg=cfg(pyo3_0_25)");
    println!("cargo::rustc-cfg=pyo3_0_25");
}
STUB_EOF

      # Recompute the file checksum so cargo doesn't notice we tampered with
      # the vendored crate. The vendor dir uses Cargo's standard
      # .cargo-checksum.json mapping path -> sha256(file).
      checksum_path="$cargoDepsCopy/source-registry-0/pyo3-stub-gen-0.9.1/.cargo-checksum.json"
      if [ -f "$checksum_path" ] && command -v python3 >/dev/null; then
        python3 - "$checksum_path" "$stub_build" <<'PY_EOF'
import hashlib, json, sys
checksum_path, build_path = sys.argv[1], sys.argv[2]
with open(checksum_path) as f:
    data = json.load(f)
with open(build_path, "rb") as f:
    data["files"]["build.rs"] = hashlib.sha256(f.read()).hexdigest()
with open(checksum_path, "w") as f:
    json.dump(data, f)
PY_EOF
      fi
    fi
  '';

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
