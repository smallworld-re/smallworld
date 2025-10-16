{ fetchFromGitHub, python3Packages, aflplusplus, maturin }:
with python3Packages;
buildPythonPackage {
  pname = "unicornafl";
  version = aflplusplus.version;
  src = fetchFromGitHub {
    owner = "AFLplusplus";
    repo = "unicornafl";
    rev = "7b79cd88c61efc1cddef89406aee2fe25ff83d54"; # from aflpp submodule at tagged version v4.34c
    hash = "sha256-N3gbSEXrlNwSixWunIR6pmWx43aBFn3b8fcpkbCoKBA=";
  };
  format = "wheel";
  # pyproject = true;
  # build-system = [ setuptools ];
  # buildInputs = [
    # maturin
  # ];
}
