# Build overrides for Python packages that need extra help to compile.
#
# This file is a nix "overlay" applied on top of the uv2nix package set.
# It receives two pairs of arguments:
#   1. { pkgs, python } — injected by callPackage in flake.nix.
#      `pkgs` is nixpkgs; `python` is the Python interpreter.
#   2. final: prev: — the standard overlay pattern.
#      `prev` is the package set before this overlay.
#      `final` is the package set after all overlays (including this one).
#
# Most overrides fall into two categories:
#   - Missing build system: uv2nix doesn't always detect that a package
#     needs setuptools to build. We declare that here.
#   - Missing native library: some packages need C libraries (libffi,
#     libunicorn) available at build time.
{ pkgs, python }:
final: prev:
let
  # Packages whose wheels/sdists need setuptools but don't declare it.
  # The format is: { <package-name>.setuptools = []; }
  # `final.resolveBuildSystem` turns this into the actual nix derivations.
  missingSetuptools = {
    arpy.setuptools = [ ];
    bitarray.setuptools = [ ];
    cppheaderparser.setuptools = [ ];
    future.setuptools = [ ];
    markupsafe.setuptools = [ ];
    mulpyplexer.setuptools = [ ];
    pypcode.setuptools = [ ];
    pyxbe.setuptools = [ ];
    pyyaml.setuptools = [ ];
    timeout-decorator.setuptools = [ ];
  };

  # Apply the setuptools override to each package listed above.
  setuptoolsOverrides = builtins.mapAttrs (
    name: spec:
    prev.${name}.overrideAttrs (old: {
      nativeBuildInputs = (old.nativeBuildInputs or [ ]) ++ final.resolveBuildSystem spec;
    })
  ) missingSetuptools;
in
{
  # angr: tell the linker where to find pyvex's shared library.
  angr = prev.angr.overrideAttrs (old: {
    autoPatchelfLibs = [ "${python.pkgs.pyvex}/lib/python3.12/site-packages/pyvex/lib" ];
  });

  # cffi: needs the C libffi headers and setuptools to build.
  cffi = prev.cffi.overrideAttrs (old: {
    nativeBuildInputs =
      (old.nativeBuildInputs or [ ])
      ++ [ pkgs.libffi ]
      ++ (final.resolveBuildSystem { setuptools = [ ]; });
  });

  # unicornafl: needs the C unicorn library at build time.
  unicornafl = prev.unicornafl.overrideAttrs (old: {
    nativeBuildInputs = (old.nativeBuildInputs or [ ]) ++ [ pkgs.unicorn ];
  });
}
// setuptoolsOverrides
