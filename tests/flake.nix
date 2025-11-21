{
  description = "Build test artifacts";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";

    deb2nix = {
      url = "gitlab:kylesferrazza/deb2nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, deb2nix }:
  let
    inherit (nixpkgs) lib;
    forAllSystems = lib.genAttrs lib.systems.flakeExposed;
  in
  {
    packages = forAllSystems (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        buildUbuntuPackage = deb2nix.buildUbuntuPackage.${system};
        gccForTriple = { triple, sha256, gccVersion ? "11" }:
          let
            gcc = buildUbuntuPackage {
              packageName = "gcc-${triple}";
              inherit sha256;
              aptDependencies = [
                "libgcc-s1"
                "binutils-${triple}"
                "libisl23"
                "libcc1-0"
              ] ++ (if gccVersion != "" then [
                "gcc-${gccVersion}-${triple}"
                "cpp-${gccVersion}-${triple}"
              ] else []);
              buildInputs = with pkgs; [
                zlib
                zstd
                gmp
                libmpc
              ];
              postBuild = ''
                rm -rf ./usr/share/doc ./usr/share/man
                cp -r ./usr/. ./.
                rm -rf ./usr
              '';
            };
          in
            gcc;
        ubuTriples = [
          # {
          #   triple = "aarch64-linux-gnu";
          #   sha256 = "sha256-lIrwzM+lNC7F10fDZ4zVZJoJZLvBWoTct2BCVsIQA1k=";
          # }
          {
            triple = "arm-linux-gnueabi";
            sha256 = "sha256-ltpc//fYwFamani3S08TIPQooT46EW27xnGa1rNR8VU=";
          }
          {
            triple = "arm-linux-gnueabihf";
            sha256 = "sha256-1NJPoKSgxGGMXiXuJBUQVOdgIw9wutqAzFFLaIJVj80=";
          }
          {
            triple = "i686-linux-gnu";
            sha256 = "sha256-t3o4ydz0n74yNZ9eoHavcZ08Jcy+ATNEl1NkFTkAoog=";
          }
          {
            triple = "mips-linux-gnu";
            gccVersion = "10";
            sha256 = "sha256-HmGGi3SgrNf6YXKtJ99K8T7JGt3XK9Hayw7+KSqVhbk=";
          }
          {
            triple = "mipsel-linux-gnu";
            gccVersion = "10";
            sha256 = "sha256-cJNg7VUr4qY02w7YTqQ1E3BXD0kgLbfNfed+BHthuWI=";
          }
          {
            triple = "mips64-linux-gnuabi64";
            gccVersion = "10";
            sha256 = "sha256-TP7wqY9t2wAr8SI6lsnGdYaHsMHb4bRGbOoQJWPfnts=";
          }
          {
            triple = "mips64el-linux-gnuabi64";
            gccVersion = "10";
            sha256 = "sha256-mHU1J6BjUaB0y3SiDV0j3iN4eTwtCRd3Aqe7mzO0N7o=";
          }
          {
            triple = "powerpc-linux-gnu";
            sha256 = "sha256-bv4HgcvNNk6DWeJgpJxvWJTwEN1hZ3PXZ0sxrgpC6/Q=";
          }
          {
            triple = "powerpc64-linux-gnu";
            sha256 = "sha256-4Q9aGhRFI+Xxz3sX/BP24GsjrmjGEiveMBKUn1NJFog=";
          }
          {
            triple = "riscv64-linux-gnu";
            sha256 = "sha256-nPalS4dgHcfJG9MJ1Qk6HuUXRBi2gnfMJqzXmuGBtKo=";
          }
          {
            triple = "xtensa-lx106";
            gccVersion = "";
            sha256 = "sha256-K/wMMP9F8hL01be3jKtalgxbrBilulnwqftbUU7j/vg=";
          }
        ];
        crossTargetCCs = map gccForTriple ubuTriples;
      in
      {
        default = pkgs.stdenv.mkDerivation
        {
          name = "smallworld-test-bins";
          src = ./.;
          buildInputs = [
            pkgs.nasm
            pkgs.pkgsCross.loongarch64-linux.stdenv.cc
            pkgs.pkgsCross.aarch64-multiplatform.stdenv.cc
          ] ++ crossTargetCCs;
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
