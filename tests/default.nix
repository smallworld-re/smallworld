{
  stdenv,
  nasm,
  zig,
  qemu-user,
  xtensaGcc,
  pkgsCross,

}:

stdenv.mkDerivation {
  name = "smallworld-test-bins";
  src = ./.;
  buildInputs = [
    nasm
    zig
    qemu-user
    xtensaGcc
    pkgsCross.ppc32.glibc
    pkgsCross.ppc64.glibc
    pkgsCross.mips64-linux-gnuabi64.glibc
    pkgsCross.mips64el-linux-gnuabi64.glibc
  ];
  env = {
    ZIG_GLOBAL_CACHE_DIR = "tmp/zig-cache";
  };
  buildPhase = ''
    make -j$(nproc)
    cd elf_core
    ulimit -c unlimited
    make
  '';
  installPhase = ''
    mkdir -p $out
    rm -r 'tmp'
    find . '(' -iname '*.elf' -o -iname '*.so' -o -iname '*.bin' -o -iname '*.o' -o -iname '*.pe' -o -iname '*.dll' ')' -print0 | tar -cvf test_binaries.tar --null -T -
    cp -r test_binaries.tar $out
  '';
}
