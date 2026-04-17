# AFL++ packaging for SmallWorld.
#
# nixpkgs does not currently ship a usable AFL++ package for Apple Silicon
# macOS. SmallWorld's Python environment already carries the `unicornafl`
# binding, so this module only needs to provide the core AFL++ CLI tools that
# drive the harness (`afl-showmap`, `afl-fuzz`, etc.) and can keep the build
# focused on the Darwin-compatible pieces.
{
  lib,
  forEachSystem,
  pkgsFor,
}:

let
  packages = forEachSystem (
    system:
    let
      pkgs = pkgsFor system;
      clang = lib.getBin pkgs.llvmPackages.clang;
      llvmConfig = "${pkgs.llvmPackages.llvm.dev}/bin/llvm-config";
      version = "4.34c";
      commonMakeFlags = [
        "CC=${clang}/bin/clang"
        "CXX=${clang}/bin/clang++"
        "LLVM_CONFIG=${llvmConfig}"
        "AFL_NO_X86=1"
        "AFL_NO_TEST_BUILD=1"
        "NO_CORESIGHT=1"
        "NO_FRIDA=1"
        "NO_NYX=1"
        "NO_QEMU=1"
        "PREFIX=${placeholder "out"}"
      ];
    in
    lib.optionalAttrs (system == "aarch64-darwin") {
      aflplusplus = pkgs.stdenv.mkDerivation (finalAttrs: {
        pname = "aflplusplus";
        inherit version;

        src = pkgs.fetchFromGitHub {
          owner = "AFLplusplus";
          repo = "AFLplusplus";
          rev = "v${finalAttrs.version}";
          hash = "sha256-ymHt746cuZ+jyWs0vB3R1qNgpgAu6pUVXp9/g9Km9JI=";
        };

        nativeBuildInputs = with pkgs; [
          cmake
          llvmPackages.bintools
          llvmPackages.clang
          llvmPackages.llvm.dev
          perl
          pkg-config
          python3
          which
        ];

        buildInputs = with pkgs; [
          coreutils
          gnugrep
          gnumake
          gnused
          libiconv
        ];

        dontConfigure = true;
        enableParallelBuilding = true;
        hardeningDisable = [ "all" ];

        preBuild = ''
          patchShebangs .
        '';

        buildPhase = ''
          runHook preBuild
          make ${lib.escapeShellArgs commonMakeFlags} all
          runHook postBuild
        '';

        installPhase = ''
          runHook preInstall
          make ${lib.escapeShellArgs commonMakeFlags} install
          runHook postInstall
        '';

        meta = {
          description = "American Fuzzy Lop plus plus with unicorn_mode for Darwin";
          homepage = "https://github.com/AFLplusplus/AFLplusplus";
          license = lib.licenses.asl20;
          platforms = [ "aarch64-darwin" ];
        };
      });
    }
  );
in
packages
