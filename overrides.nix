{ pkgs, python }:
final: prev:
let
  buildSystemOverrides = {
    bitarray.setuptools = [];
    cppheaderparser.setuptools = [];
    future.setuptools = [];
    markupsafe.setuptools = [];
    mulpyplexer.setuptools = [];
    pypcode.setuptools = [];
    pyyaml.setuptools = [];
    timeout-decorator.setuptools = [];
  };
  mappedBuildSystemOverrides = builtins.mapAttrs (
    name: spec:
    prev.${name}.overrideAttrs (old: {
      nativeBuildInputs = (old.nativeBuildInputs or []) ++ final.resolveBuildSystem spec;
    })
  ) buildSystemOverrides;
in
{
  angr = prev.angr.overrideAttrs (old: {
    autoPatchelfLibs = ["${python.pkgs.pyvex}/lib/python3.12/site-packages/pyvex/lib"];
  });

  cffi = prev.cffi.overrideAttrs (old: {
    nativeBuildInputs = (old.nativeBuildInputs or []) ++ [
      pkgs.libffi
    ] ++ (final.resolveBuildSystem {
      setuptools = [];
    });
  });

  unicornafl = prev.unicornafl.overrideAttrs (old: {
    nativeBuildInputs = (old.nativeBuildInputs or []) ++ [pkgs.unicorn];
  });

} // mappedBuildSystemOverrides
