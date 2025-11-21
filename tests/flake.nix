{
  description = "Build test artifacts";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";

    nixpkgs-esp-dev = {
      url = "github:mirrexagon/nixpkgs-esp-dev";
      flake = false;
    };
  };

  outputs =
    {
      self,
      nixpkgs,
    }:
    let
      inherit (nixpkgs) lib;
      forAllSystems = lib.genAttrs lib.systems.flakeExposed;
    in
    {
      packages = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          nixCrossTargets = [
            "aarch64-multiplatform"
            "arm-embedded"
            "armv7l-hf-multiplatform"
            "mips-linux-gnu"
            "mipsel-linux-gnu"
            "mips64-linux-gnuabi64"
            "mips64el-linux-gnuabi64"
            "riscv64"
            "ppc32"
            "ppc64"
            "loongarch64-linux"
          ];
          nixCrossTargetCCs = map (target: pkgs.pkgsCross.${target}.stdenv.cc) nixCrossTargets;
        in
        {
          default = pkgs.stdenv.mkDerivation {
            name = "smallworld-test-bins";
            src = ./.;
            buildInputs = [
              pkgs.nasm
              # get the compilers that aren't in pkgsCross
              # nixpkgs.legacyPackages.x86_64-linux.stdenv.cc
              pkgs.gcc
            ] ++ nixCrossTargetCCs;
            buildPhase = ''
              make aarch64
              make amd64
              make armel
              make armhf
              make i386
              make la64
              make mips
              make mipsel
              make mips64
              make mips64el
              make ppc
              make ppc64
              make riscv64
              make xtensa
              make amd64_mingw
              make i386_mingw
            '';
            installPhase = ''
              mkdir -p $out
              find -L . -regextype posix-extended -type f ! -regex "(.*\.(bin|elf|o|so|pe|dll))$" -delete
              cp -r . $out
            '';
          };
        }
      );
    };
}
