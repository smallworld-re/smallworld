# CI-only flake for smallworld-re.
#
# The main flake exposes the package and developer shell that downstream users
# should consume. This separate flake keeps heavyweight test/demo toolchains
# out of that public interface.
{
  description = "smallworld-re CI outputs";

  inputs = {
    smallworld.url = "..";
    nixpkgs.follows = "smallworld/nixpkgs";

    # Xtensa cross-compiler used to build some test binaries.
    nixpkgs-esp-dev = {
      url = "github:mirrexagon/nixpkgs-esp-dev";
      flake = false;
    };

    # Zephyr tooling only needed for the RTOS demo artifact.
    zephyr-nix = {
      url = "github:adisbladis/zephyr-nix";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.pyproject-nix.follows = "smallworld/pyproject-nix";
    };
    west2nix = {
      url = "github:adisbladis/west2nix";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.zephyr-nix.follows = "zephyr-nix";
    };
  };

  outputs =
    {
      nixpkgs,
      nixpkgs-esp-dev,
      zephyr-nix,
      west2nix,
      ...
    }:
    let
      lib = nixpkgs.lib;
      systems = lib.systems.flakeExposed;
      forAllSystems = lib.genAttrs systems;
      pkgsFor = system: nixpkgs.legacyPackages.${system};
      x86LinuxPkgs = pkgsFor "x86_64-linux";

      darwinArtifactSystemFor =
        system: if system == "aarch64-darwin" then "aarch64-linux" else "x86_64-linux";

      mkXtensaGcc =
        system:
        let
          pkgs = pkgsFor system;
        in
        if system == "aarch64-linux" then
          pkgs.stdenv.mkDerivation rec {
            pname = "gcc-xtensa-lx106-elf-bin";
            version = "2020r3";

            src = pkgs.fetchurl {
              url = "https://dl.espressif.com/dl/xtensa-lx106-elf-gcc8_4_0-esp-${version}-linux-amd64.tar.gz";
              hash = "sha256-ChgEteIjHG24tyr2vCoPmltplM+6KZVtQSZREJ8T/n4=";
            };

            nativeBuildInputs = [
              pkgs.file
              pkgs.makeWrapper
              pkgs.patchelf
            ];

            installPhase = ''
              cp -r . "$out"

              x86_interp=${x86LinuxPkgs.stdenv.cc.bintools.dynamicLinker}
              x86_lib_path="${lib.makeLibraryPath [ x86LinuxPkgs.stdenv.cc.cc ]}:$out/lib:$out/lib64"
              qemu_x86_64=${pkgs.qemu-user}/bin/qemu-x86_64

              find "$out" -type f -perm -0100 | while read -r f; do
                if ! file "$f" | grep -q 'ELF 64-bit LSB .*x86-64'; then
                  continue
                fi

                patchelf --set-interpreter "$x86_interp" "$f" || true
                patchelf --set-rpath "$x86_lib_path" "$f" || true

                mv "$f" "$f.real"
                makeWrapper "$qemu_x86_64" "$f" \
                  --add-flags "-L ${x86LinuxPkgs.glibc.outPath}" \
                  --add-flags "$f.real" \
                  --set-default LD_LIBRARY_PATH "$x86_lib_path"
              done
            '';
          }
        else
          pkgs.callPackage "${nixpkgs-esp-dev}/pkgs/esp8266/gcc-xtensa-lx106-elf-bin.nix" { };

      mkLinuxArtifacts =
        system:
        let
          pkgs = pkgsFor system;
          xtensaGcc = mkXtensaGcc system;

          tests = pkgs.callPackage ../tests {
            inherit xtensaGcc;
            x86_64_glibc_path = x86LinuxPkgs.glibc.outPath;
          };

          rtos_demo = pkgs.callPackage ../use_cases/rtos_demo {
            zephyr = zephyr-nix.packages.${system};
            west2nix = pkgs.callPackage west2nix.lib.mkWest2nix { };
          };
        in
        {
          inherit tests rtos_demo;
        };

      mkLinuxDevShell =
        system:
        let
          pkgs = pkgsFor system;
          artifacts = mkLinuxArtifacts system;
        in
        pkgs.mkShell {
          inputsFrom = [
            artifacts.tests
            artifacts.rtos_demo
          ];

          env = {
            AMD64_SYSROOT = x86LinuxPkgs.glibc.outPath;
            AARCH64_SYSROOT = pkgs.pkgsCross.aarch64-multiplatform.glibc.outPath;
            PPC_SYSROOT = pkgs.pkgsCross.ppc32.glibc.outPath;
          };

          shellHook = ''
            export ZIG_GLOBAL_CACHE_DIR=/tmp/zig-cache
          '';
        };
    in
    {
      devShells = forAllSystems (
        system:
        if lib.hasSuffix "-linux" system then
          {
            default = mkLinuxDevShell system;
          }
        else
          { }
      );

      packages = forAllSystems (
        system:
        if lib.hasSuffix "-linux" system then
          mkLinuxArtifacts system
        else if lib.hasSuffix "-darwin" system then
          # macOS cannot build these artifacts natively because part of the
          # test bundle generates Linux guest core dumps under qemu-user.
          # Expose a Linux derivation that matches the Linux builder most
          # commonly available for that Mac. Apple Silicon Macs usually have
          # an aarch64-linux builder, while Intel Macs typically use x86_64.
          mkLinuxArtifacts (darwinArtifactSystemFor system)
        else
          { }
      );
    };
}
