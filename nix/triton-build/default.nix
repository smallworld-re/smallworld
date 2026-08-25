# Repo-local packaging for the `triton-library` Python module used by
# SmallWorld's Triton backend (JonathanSalwan's Triton; import name `triton`).
#
# Unlike the Styx backend (a Rust/maturin wheel), Triton is a C++ library whose
# CPython bindings are compiled by CMake. Triton's own `setup.py` drives that
# CMake build (target `python-triton`) and copies the resulting `triton.so`
# into the wheel, so we set `dontUseCmakeConfigure` and let setup.py run cmake,
# feeding it Z3/Capstone locations through the environment variables setup.py
# forwards into the cmake cache.
#
# We build from a pinned upstream revision rather than the PyPI release because
# only recent revisions expose the RISC-V architecture (triton.ARCH.RV32/RV64);
# keep `version` in sync with setup.py at the pinned rev.
#
# IMPORTANT: this is JonathanSalwan's Triton. It is unrelated to nixpkgs'
# `triton` (TritonDataCenter's Node.js CLI) and to `python3Packages.triton`
# (OpenAI's GPU compiler). Do not substitute either for this build.
{
  lib,
  fetchFromGitHub,
  cmake,
  z3,
  capstone,
}:
let
  src = fetchFromGitHub {
    owner = "JonathanSalwan";
    repo = "Triton";
    rev = "bc84cf745e99768e07d51dcd734eba35c59f1b3e";
    hash = "sha256-mj+WnlzUEmApBLe4LyWg/oZveokAEt8UpGDgJ6Tu4Ig=";
  };
  # SmallWorld's supported dev/CI target is Linux; Triton's setup.py copies
  # triton.so on Linux.
  sharedLibExt = ".so";
in
ps:
ps.buildPythonPackage {
  pname = "triton-library";
  # Keep in sync with setup.py at the pinned rev (VERSION_* + RELEASE_CANDIDATE).
  version = "1.0.0rc4";
  inherit src;
  pyproject = true;
  build-system = [ ps.setuptools ];

  # setup.py runs its own out-of-tree cmake configure/build; keep the nixpkgs
  # cmake hook from taking over the configure phase (same idea as the Styx
  # builder's dontUseCmakeConfigure).
  dontUseCmakeConfigure = true;

  nativeBuildInputs = [ cmake ];
  buildInputs = [
    z3
    capstone
  ];

  postPatch = ''
    # Respect the sandbox core count instead of the hardcoded -j4.
    substituteInPlace setup.py \
      --replace-fail "'-j4'" "'-j' + os.environ.get('NIX_BUILD_CORES', '4')"
  '';

  # Triton's FindZ3/FindCAPSTONE modules use plain find_path/find_library, and
  # setup.py forwards these env vars into the cmake cache. Point them straight
  # at the Nix store paths for a deterministic hand-off, and keep the Z3
  # interface on (required for the AstContext bridge the symbolic backend uses).
  env = {
    Z3_INTERFACE = "ON";
    Z3_INCLUDE_DIRS = "${lib.getDev z3}/include";
    Z3_LIBRARIES = "${lib.getLib z3}/lib/libz3${sharedLibExt}";
    CAPSTONE_INCLUDE_DIRS = "${lib.getDev capstone}/include";
    CAPSTONE_LIBRARIES = "${lib.getLib capstone}/lib/libcapstone${sharedLibExt}";
    CMAKE_PREFIX_PATH = "${lib.getDev z3};${lib.getDev capstone}";
    # The autocomplete .pyi target imports the freshly built module in a
    # separate cmake target; skip it to keep the build lean and offline-safe.
    PYTHON_BINDINGS_AUTOCOMPLETE = "OFF";
  };

  # Z3 and Capstone are linked natively; there are no Python runtime deps.
  dependencies = [ ];

  pythonImportsCheck = [ "triton" ];
}
