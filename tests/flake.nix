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
      nixpkgs-esp-dev,
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
          # nixCrossTargets = [
          #   "aarch64-multiplatform"
          #   "arm-embedded"
          #   "armv7l-hf-multiplatform"
          #   "mips-linux-gnu"
          #   "mipsel-linux-gnu"
          #   "mips64-linux-gnuabi64"
          #   "mips64el-linux-gnuabi64"
          #   "riscv64"
          #   "ppc32"
          #   "ppc64"
          #   "loongarch64-linux"
          #   "mingwW64"
          #   "mingw32"
          # ];
          # nixCrossTargetCCs = map (target: pkgs.pkgsCross.${target}.stdenv.cc) nixCrossTargets;
          # xtensaGcc = pkgs.callPackage "${nixpkgs-esp-dev}/pkgs/esp8266/gcc-xtensa-lx106-elf-bin.nix" { };
        in
        {
          default = pkgs.stdenv.mkDerivation {
            name = "smallworld-test-bins";
            src = ./.;
            buildInputs = [
              pkgs.nasm
              pkgs.zig
              pkgs.qemu-user
              # pkgs.breakpointHook
            ];
            preBuild = ''
              export HOME=$(mktemp -d)
            '';
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
              # make mips64el
              make ppc
              make ppc64
              make riscv64
              # make xtensa
              make amd64_mingw
              make i386_mingw
              # cd elf_core
              # ulimit -c unlimited
              # make
            '';
            installPhase = ''
              mkdir -p $out
              find . '(' -iname '*.elf' -o -iname '*.so' -o -iname '*.bin' -o -iname '*.o' -o -iname '*.pe' -o -iname '*.dll' ')' -print0 | tar -cvf test_binaries.tar --null -T -
              cp -r test_binaries.tar $out
            '';
          };
        }
      );
    };
}
