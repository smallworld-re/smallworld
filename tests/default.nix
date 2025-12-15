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
    pkgsCross.aarch64-multiplatform.glibc
    pkgsCross.ppc32.glibc
    # pkgsCross.ppc64.glibc
    # pkgsCross.mips64-linux-gnuabi64.glibc
    # pkgsCross.mips64el-linux-gnuabi64.glibc
  ];
  env = {
    ZIG_GLOBAL_CACHE_DIR = "tmp/zig-cache";
    AMD64_SYSROOT = x86_64_glibc_path;
    AARCH64_SYSROOT = pkgsCross.aarch64-multiplatform.glibc.outPath;
    PPC_SYSROOT = pkgsCross.ppc32.glibc.outPath;
  };
  buildPhase = ''
    make -j$(nproc)
    cd elf_core
    ulimit -c unlimited
    make
  '';
  installPhase = ''
    mkdir -p $out
    cd ..
    find . '(' -iname '*.elf' -o -iname '*.so' -o -iname '*.bin' -o -iname '*.o' -o -iname '*.pe' -o -iname '*.dll' ')' -print0 | tar -cvf test_binaries.tar --null -T -
    cp -r test_binaries.tar $out
  '';
}
