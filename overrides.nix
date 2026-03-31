# Small fixes for third-party Python packages pulled in from `uv.lock`.
#
# uv2nix builds almost everything directly from the lock file, but a few
# upstream packages still need extra hints:
#   - some forget to declare `setuptools` as a build dependency
#   - some need a native system library at build time
#   - some ship wheel metadata that is stricter than the versions we lock
#
# This file is applied on top of the uv2nix-generated Python package set.
# In Nix terms, `prev` is the package set before our fixes and `final` is the
# package set after our fixes have been added.
{ pkgs, python }:
final: prev:
let
  # Append extra native build inputs to one package.
  addNativeBuildInputs =
    package: extraInputs:
    prev.${package}.overrideAttrs (old: {
      nativeBuildInputs = (old.nativeBuildInputs or [ ]) ++ extraInputs;
    });

  # Many older Python packages build fine once setuptools is present, even
  # though they forgot to declare it themselves.
  addSetuptools =
    package: addNativeBuildInputs package (final.resolveBuildSystem { setuptools = [ ]; });

  # A small group of packages all need the same setuptools fix.
  setuptoolsOverrides = builtins.listToAttrs (
    map (name: {
      inherit name;
      value = addSetuptools name;
    }) [
      "arpy"
      "bitarray"
      "cppheaderparser"
      "future"
      "markupsafe"
      "mulpyplexer"
      "pypcode"
      "pyxbe"
      "pyyaml"
      "timeout-decorator"
    ]
  );
in
setuptoolsOverrides
// {
  # angr: tell the linker where to find pyvex's shared library.
  angr = prev.angr.overrideAttrs (old: {
    autoPatchelfLibs = [ "${python.pkgs.pyvex}/lib/python3.12/site-packages/pyvex/lib" ];
  });

  # claripy depends on z3-solver, but nixpkgs' z3 package does not install
  # dist-info metadata, so the wheel runtime dependency check would fail.
  claripy = prev.claripy.overrideAttrs (old: {
    pythonRemoveDeps = (old.pythonRemoveDeps or [ ]) ++ [ "z3-solver" ];
  });

  # cffi: needs the C libffi headers and setuptools to build.
  cffi = addNativeBuildInputs "cffi" (
    [ pkgs.libffi ] ++ final.resolveBuildSystem { setuptools = [ ]; }
  );

  # cle's wheel metadata still hard-pins arpy, but the locked dependency set
  # resolves a newer arpy release. Skip the wheel runtime metadata check.
  cle = prev.cle.overrideAttrs (_old: {
    dontCheckRuntimeDeps = true;
  });

  # pyghidra pins jpype1 too tightly in wheel metadata; nixpkgs already
  # relaxes this so newer jpype1 releases remain usable. Our uv2nix path
  # installs from wheels, so disable the pre-install runtime metadata check.
  pyghidra = prev.pyghidra.overrideAttrs (old: {
    pythonRelaxDeps = (old.pythonRelaxDeps or [ ]) ++ [ "jpype1" ];
    pythonRemoveDeps = (old.pythonRemoveDeps or [ ]) ++ [ "jpype1" ];
    dontCheckRuntimeDeps = true;
  });

  # unicornafl: needs the C unicorn library at build time.
  unicornafl = addNativeBuildInputs "unicornafl" [ pkgs.unicorn ];
}
