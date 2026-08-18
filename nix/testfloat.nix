# Berkeley TestFloat, built from upstream rather than vendored.
#
# TestFloat is the reference conformance suite for IEEE-754 arithmetic: it
# generates hard operand patterns (denormals, boundary exponents, ties, signed
# zeroes, NaNs) and checks results against Berkeley SoftFloat. SmallWorld uses
# the two data-driven tools rather than the self-test programs:
#
#   testfloat_gen <func>   emits "<operands...> <reference> <flags>" per line
#   testfloat_ver <func>   reads "<operands...> <result> <flags>" and re-derives
#                          the reference with SoftFloat, reporting mismatches
#
# so the harness can drop an emulated FPU into the middle: take the operands
# from `gen`, compute the result on the target, and hand the answer to `ver`.
#
# TestFloat does not build standalone - its Makefile expects SoftFloat as a
# sibling directory (SOFTFLOAT_DIR ?= ../../../SoftFloat-3e) and links its
# static library - so both are fetched and built here.
#
# Note on SPECIALIZE_TYPE: SoftFloat's build selects *NaN-propagation
# semantics*, not a host architecture - 8086-SSE, ARM-VFPv2, RISCV and so on
# differ in default-NaN encoding and which operand's payload survives. One build
# therefore cannot be bit-exact about NaN payloads for every target we emulate.
# That is fine, because `testfloat_ver` only compares NaN payloads under
# `-checkNaNs`, which the harness deliberately leaves off; everything else -
# finite results, infinities, signed zeroes and the five exception flags - is
# architecture-independent and is compared in full.
{
  lib,
  stdenv,
  fetchurl,
  unzip,
}:

let
  version = "3e";

  softfloatSrc = fetchurl {
    url = "http://www.jhauser.us/arithmetic/SoftFloat-${version}.zip";
    hash = "sha256-IRMM6IXTXB/nP8HhvyJEF4Fn4FxnR8rV9FDMmRcUx0Y=";
  };

  testfloatSrc = fetchurl {
    url = "http://www.jhauser.us/arithmetic/TestFloat-${version}.zip";
    hash = "sha256-bUvfAJa0imU6pZ/CA6nl/hi1pY16G3FRB8cUZ3agqtY=";
  };

  # Upstream ships one build directory per host configuration. Nothing in the
  # x86-64 one is actually x86-specific - it sets LITTLEENDIAN, asks for GCC's
  # __int128 and count-leading-zeros builtins, and picks the 8086-SSE NaN
  # specialization - so it serves any little-endian 64-bit GCC host.
  platform = "Linux-x86_64-GCC";
in
stdenv.mkDerivation {
  pname = "berkeley-testfloat";
  inherit version;

  srcs = [
    softfloatSrc
    testfloatSrc
  ];
  sourceRoot = ".";

  nativeBuildInputs = [ unzip ];

  # The zips unpack to SoftFloat-3e/ and TestFloat-3e/ side by side, which is
  # exactly the layout TestFloat's Makefile expects.
  unpackPhase = ''
    runHook preUnpack
    for src in $srcs; do
      unzip -q "$src"
    done
    runHook postUnpack
  '';

  buildPhase = ''
    runHook preBuild
    make -C SoftFloat-${version}/build/${platform} -j"$NIX_BUILD_CORES"
    make -C TestFloat-${version}/build/${platform} -j"$NIX_BUILD_CORES"
    runHook postBuild
  '';

  installPhase = ''
    runHook preInstall
    mkdir -p "$out/bin"
    for tool in testfloat_gen testfloat_ver testfloat testsoftfloat timesoftfloat; do
      install -Dm755 "TestFloat-${version}/build/${platform}/$tool" "$out/bin/$tool"
    done
    runHook postInstall
  '';

  doInstallCheck = true;
  installCheckPhase = ''
    runHook preInstallCheck
    # Round-tripping the generator's own output through the verifier proves both
    # tools work and agree: `gen` emits SoftFloat's reference answers, so `ver`
    # must find no errors in them.
    #
    # Deliberately staged through files rather than piped: `head`/`grep -q`
    # close the pipe as soon as they are satisfied, which kills testfloat_gen
    # with SIGPIPE and fails the phase under `set -o pipefail` even though the
    # comparison itself succeeded. 46464 is testfloat_gen's minimum case count
    # for a two-operand f32 function.
    "$out/bin/testfloat_gen" -n 46464 f32_add > cases.txt
    "$out/bin/testfloat_ver" f32_add < cases.txt > verified.txt
    cat verified.txt
    grep -q "no errors found" verified.txt
    runHook postInstallCheck
  '';

  meta = with lib; {
    description = "Berkeley TestFloat: IEEE-754 arithmetic conformance test suite";
    homepage = "http://www.jhauser.us/arithmetic/TestFloat.html";
    license = licenses.bsd3;
    # Only the little-endian 64-bit Linux hosts the `Linux-x86_64-GCC` build
    # directory actually serves: it sets LITTLEENDIAN and enables
    # SOFTFLOAT_INTRINSIC_INT128, so `unsigned __int128` has to exist. Claiming
    # all of `platforms.linux` would offer i686/armv7 builds that cannot compile.
    platforms = intersectLists platforms.linux (
      platforms.x86_64 ++ platforms.aarch64 ++ platforms.riscv64
    );
  };
}
