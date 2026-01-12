{
  ghidra,
  stdenv,
  pyprojectHook,
  resolveBuildSystem,
}:
stdenv.mkDerivation {
  pname = "pyghidra";
  version = ghidra.version;
  src = "${ghidra}/lib/ghidra/Ghidra/Features/PyGhidra/pypkg";
  preBuild = ''
    rm -rv ./dist
  '';
  nativeBuildInputs = [
    pyprojectHook
  ]
  ++ (resolveBuildSystem {
    setuptools = [ ];
  });
  passthru.dependencies = {
    jpype1 = [ ];
  };
}
