{
  lib,
  stdenv,
  nasm,
  zstd,
  zig,
  gdb,
  qemu-user,
  sdcc,
  ppcVleBinutils,
  superHBinutils,
  tricoreGcc,
  v850Binutils,
  xtensaGcc,
  pkgsCross,
  x86_64_glibc_path,
}:

let
  # zig's global cache pre-populated with every per-target runtime library
  # (libc stubs, CRT files, compiler-rt) the tests link against. Building
  # those is most of a cold test build, and they depend only on zig and the
  # Makefile's targets and flags, so this derivation's source is just the
  # files zig_warmup.mk reads: editing or adding a test does not rebuild it.
  # Stored as a zstd tarball to keep it small in the Nix store.
  zigCache = stdenv.mkDerivation {
    name = "smallworld-test-zig-cache";
    src = lib.fileset.toSource {
      root = ./.;
      fileset = lib.fileset.unions [
        ./Makefile
        ./zig_warmup.mk
        ./mips_linkerscript.ld
      ];
    };
    nativeBuildInputs = [
      zig
      zstd
    ];
    buildPhase = ''
      export ZIG_GLOBAL_CACHE_DIR=$TMPDIR/zig-cache
      make -f zig_warmup.mk -j$((2 * NIX_BUILD_CORES))
    '';
    installPhase = ''
      mkdir -p $out
      # tmp/ only holds in-progress work.
      tar -C "$ZIG_GLOBAL_CACHE_DIR" --exclude=./tmp -cf - . \
        | zstd -T"''${NIX_BUILD_CORES:-0}" -o $out/zig-cache.tar.zst
    '';
  };
in
stdenv.mkDerivation {
  name = "smallworld-test-bins";
  src = ./.;
  nativeBuildInputs = [
    nasm
    zstd
    zig
    qemu-user
    gdb
    ppcVleBinutils
    superHBinutils
    tricoreGcc
    v850Binutils
    xtensaGcc
    pkgsCross.m68k.stdenv.cc
    # Builds elf_core.ppc64.elf; see the PPC64_GLIBC_CC note in the Makefile.
    pkgsCross.ppc64.stdenv.cc
    # Builds the 8051 tests; see mcs51_asm.sh and mcs51_cc.sh.
    sdcc
  ];
  buildInputs = [
    pkgsCross.m68k.glibc
    pkgsCross.aarch64-multiplatform.glibc
    pkgsCross.ppc32.glibc
    pkgsCross.ppc64.glibc
  ];
  env = {
    AMD64_SYSROOT = x86_64_glibc_path;
    AARCH64_SYSROOT = pkgsCross.aarch64-multiplatform.glibc.outPath;
    PPC_SYSROOT = pkgsCross.ppc32.glibc.outPath;
    PPC64_SYSROOT = pkgsCross.ppc64.glibc.outPath;
  };
  shellHook = ''
    export ZIG_GLOBAL_CACHE_DIR=/tmp/zig-cache
  '';
  buildPhase = ''
    # The test Makefile expects these generic wrapper scripts to exist under
    # architecture-specific tool names for the m68k and Xtensa toolchains.
    ln -sf asm_wrapper.sh m68k-unknown-linux-gnu-asm
    ln -sf elf_wrapper.sh m68k-unknown-linux-gnu-elfasm
    ln -sf asm_wrapper.sh tricore-elf-asm
    ln -sf elf_wrapper.sh tricore-elf-elfasm
    ln -sf asm_wrapper.sh xtensa-lx106-elf-asm
    ln -sf elf_wrapper.sh xtensa-lx106-elf-elfasm
    # One SuperH binutils serves SH-4 big/little and SH-2A; the Makefile picks
    # the generation and endianness with per-platform ASFLAGS, and
    # elf_wrapper.sh mirrors that choice onto `ld` as -EB/-EL.
    ln -sf asm_wrapper.sh sh4-unknown-linux-gnu-asm
    ln -sf elf_wrapper.sh sh4-unknown-linux-gnu-elfasm
    ln -sf asm_wrapper.sh v850-elf-asm
    ln -sf elf_wrapper.sh v850-elf-elfasm
    # zig cannot assemble PowerPC VLE; GNU as does, given -mvle.
    ln -sf asm_wrapper.sh powerpc-none-eabi-asm
    ln -sf elf_wrapper.sh powerpc-none-eabi-elfasm

    # Start from the pre-built runtime libraries; see zigCache above.
    export ZIG_GLOBAL_CACHE_DIR=$TMPDIR/zig-cache
    mkdir -p "$ZIG_GLOBAL_CACHE_DIR"
    tar -C "$ZIG_GLOBAL_CACHE_DIR" --zstd -xf ${zigCache}/zig-cache.tar.zst

    # Oversubscribe: jobs that block on zig's global cache lock (anything
    # zigCache missed) would otherwise leave CPUs idle.
    make -j$((2 * NIX_BUILD_CORES))
    cd elf_core
    ulimit -c unlimited
    make
  '';
  installPhase = ''
    find .. '(' -iname '*.elf' -o -iname '*.so' -o -iname '*.bin' -o -iname '*.o' -o -iname '*.pe' -o -iname '*.dll' -o -iname '*.core' -o -iname '*.registers' -o -iname '*.ihx' -o -iname '*.map' ')' -print0 \
      | tar -cvf - --null -T - \
      | zstd -T"''${NIX_BUILD_CORES:-0}" -o test_binaries.tar.zst
    mkdir -p $out
    cp test_binaries.tar.zst $out
  '';
  passthru = { inherit zigCache; };
}
