{
  stdenv,
  nasm,
  zig,
  gdb,
  qemu-user,
  xtensaGcc,
  pkgsCross,
  x86_64_glibc_path,
}:

stdenv.mkDerivation {
  name = "smallworld-test-bins";
  src = ./.;
  buildInputs = [
    nasm
    zig
    qemu-user
    gdb
    xtensaGcc
    pkgsCross.m68k.stdenv.cc
    pkgsCross.m68k.glibc
    pkgsCross.aarch64-multiplatform.glibc
    pkgsCross.ppc32.glibc
  ];
  env = {
    AMD64_SYSROOT = x86_64_glibc_path;
    AARCH64_SYSROOT = pkgsCross.aarch64-multiplatform.glibc.outPath;
    PPC_SYSROOT = pkgsCross.ppc32.glibc.outPath;
  };
  shellHook = ''
    export ZIG_GLOBAL_CACHE_DIR=/tmp/zig-cache
  '';
  buildPhase = ''
    # The test Makefile expects these generic wrapper scripts to exist under
    # architecture-specific tool names for the m68k and Xtensa toolchains.
    ln -sf asm_wrapper.sh m68k-unknown-linux-gnu-asm
    ln -sf elf_wrapper.sh m68k-unknown-linux-gnu-elfasm
    ln -sf asm_wrapper.sh xtensa-lx106-elf-asm
    ln -sf elf_wrapper.sh xtensa-lx106-elf-elfasm

    make -j$(nproc)
    cd elf_core
    ulimit -c unlimited
    make
  '';
  installPhase = ''
    find .. '(' -iname '*.elf' -o -iname '*.so' -o -iname '*.bin' -o -iname '*.o' -o -iname '*.pe' -o -iname '*.dll' -o -iname '*.core' -o -iname '*.registers' ')' -print0 | tar -cvf test_binaries.tar --null -T -
    mkdir -p $out
    cp -r test_binaries.tar $out
  '';
}
