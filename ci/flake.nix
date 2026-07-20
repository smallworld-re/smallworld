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
      mkX86LinuxBinaryFixup =
        {
          pkgs,
          runtimeLibraries,
          wrapWithQemu ? false,
        }:
        let
          x86LibPath = "${lib.makeLibraryPath runtimeLibraries}:$out/lib:$out/lib64";
        in
        ''
          x86_interp=${x86LinuxPkgs.stdenv.cc.bintools.dynamicLinker}
          x86_lib_path="${x86LibPath}"
          ${lib.optionalString wrapWithQemu ''
            qemu_x86_64=${pkgs.qemu-user}/bin/qemu-x86_64
          ''}

          find "$out" -type f -perm -0100 | while read -r f; do
            if ! file "$f" | grep -q 'ELF 64-bit LSB .*x86-64'; then
              continue
            fi

            patchelf --set-interpreter "$x86_interp" "$f" || true
            patchelf --set-rpath "$x86_lib_path" "$f" || true

            ${lib.optionalString wrapWithQemu ''
              mv "$f" "$f.real"
              makeWrapper "$qemu_x86_64" "$f" \
                --add-flags "-L ${x86LinuxPkgs.glibc.outPath}" \
                --add-flags "$f.real" \
                --set-default LD_LIBRARY_PATH "$x86_lib_path"
            ''}
          done
        '';

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
              ${mkX86LinuxBinaryFixup {
                inherit pkgs;
                runtimeLibraries = [
                  x86LinuxPkgs.stdenv.cc.cc
                  x86LinuxPkgs.zstd
                  x86LinuxPkgs.ncurses
                ];
                wrapWithQemu = true;
              }}
            '';
          }
        else
          pkgs.callPackage "${nixpkgs-esp-dev}/pkgs/esp8266/gcc-xtensa-lx106-elf-bin.nix" { };

      mkTricoreGcc =
        system:
        let
          pkgs = pkgsFor system;
          tricoreSrc = pkgs.fetchurl {
            url = "https://github.com/NoMore201/tricore-gcc-toolchain/releases/download/13.4-20250801/tricore-gcc-13.4-20250801-linux.tar.gz";
            hash = "sha256-IiVY76PacDTe8u8cEWE7tYJ+EM782OsjnIFrpYSPnGY=";
          };
        in
        if system == "x86_64-linux" then
          pkgs.stdenv.mkDerivation rec {
            pname = "tricore-gcc-toolchain-bin";
            version = "13.4-20250801";
            src = tricoreSrc;
            sourceRoot = ".";

            nativeBuildInputs = [
              pkgs.file
              pkgs.patchelf
            ];

            installPhase = ''
              mkdir -p "$out"
              cp -r ./* "$out"/
              ${mkX86LinuxBinaryFixup {
                inherit pkgs;
                runtimeLibraries = [
                  x86LinuxPkgs.stdenv.cc.cc
                  x86LinuxPkgs.zstd
                  x86LinuxPkgs.ncurses
                ];
              }}
            '';
          }
        else
          pkgs.stdenv.mkDerivation rec {
            pname = "tricore-gcc-toolchain-bin";
            version = "13.4-20250801";
            src = tricoreSrc;
            sourceRoot = ".";

            nativeBuildInputs = [
              pkgs.file
              pkgs.makeWrapper
              pkgs.patchelf
            ];

            installPhase = ''
              mkdir -p "$out"
              cp -r ./* "$out"/
              ${mkX86LinuxBinaryFixup {
                inherit pkgs;
                runtimeLibraries = [ x86LinuxPkgs.stdenv.cc.cc ];
                wrapWithQemu = true;
              }}
            '';
          };

      mkLinuxArtifacts =
        system:
        let
          pkgs = pkgsFor system;
          xtensaGcc = mkXtensaGcc system;
          tricoreGcc = mkTricoreGcc system;

          tests = pkgs.callPackage ../tests {
            inherit tricoreGcc xtensaGcc;
            x86_64_glibc_path = x86LinuxPkgs.glibc.outPath;
          };

          rtos_demo = pkgs.callPackage ../use_cases/rtos_demo {
            zephyr =
              let
                zephyrPkgs = zephyr-nix.packages.${system};

                # nixpkgs bumped setuptools-scm to 10.x, but spsdk 3.9.0 (pulled
                # in by zephyr's pythonEnv) still pins "setuptools_scm<10" in its
                # build-system requires. zephyr-nix already carries a fix for
                # this, but it targets the older "setuptools_scm<8.2" spelling
                # via a non-fatal --replace-warn, so it silently no-ops and the
                # spsdk wheel build fails its build-dependency check. Relax the
                # pin ourselves in prePatch; zephyr-nix only overwrites
                # postPatch, so this survives its overridePythonAttrs.
                #
                # patool's test suite is likewise broken at this nixpkgs
                # revision: a libmagic/`file` update changed archive MIME
                # detection and the archive-program lookup, so ~a dozen of its
                # tests now fail during the build. These are test-environment
                # regressions, not defects in patool itself (which only needs
                # to extract SDK archives), so skip its check phase.
                pythonFixesOverlay = _final: prev: {
                  pythonPackagesExtensions = prev.pythonPackagesExtensions ++ [
                    (_pyfinal: pyprev: {
                      spsdk = pyprev.spsdk.overridePythonAttrs (old: {
                        prePatch = (old.prePatch or "") + ''
                          substituteInPlace pyproject.toml \
                            --replace-fail "setuptools_scm<10" "setuptools_scm"
                        '';
                      });
                      patool = pyprev.patool.overridePythonAttrs (_old: {
                        doCheck = false;
                        doInstallCheck = false;
                      });
                    })
                  ];
                };

                # Only pythonEnv depends on these packages, so rebuild just that
                # against the patched package set (reusing zephyr-nix's own
                # python.nix and its locked inputs); the SDK and host tools are
                # untouched.
                pkgsWithPythonFixes = (pkgsFor system).extend pythonFixesOverlay;
                fixedPythonEnv = pkgsWithPythonFixes.callPackage (zephyr-nix + "/python.nix") {
                  zephyr-src = zephyr-nix.inputs.zephyr;
                  pyproject-nix = zephyr-nix.inputs.pyproject-nix;
                  pkgs = pkgsWithPythonFixes;
                };

                # openocd-zephyr's udevCheckPhase runs udevadm verify, which
                # requires a live kernel udev subsystem absent in CI sandboxes.
                openocdFixed = zephyrPkgs.openocd-zephyr.overrideAttrs (_: {
                  doInstallCheck = false;
                });
              in
              zephyrPkgs
              // {
                pythonEnv = fixedPythonEnv;
                hosttools-nix = zephyrPkgs.hosttools-nix.overrideAttrs (old: {
                  propagatedBuildInputs = map (
                    dep: if dep == zephyrPkgs.openocd-zephyr then openocdFixed else dep
                  ) old.propagatedBuildInputs;
                });
              };
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
