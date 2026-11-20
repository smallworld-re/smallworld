# Ghidra with SmallWorld's fixes to its Intel 8051 language.
#
# Ghidra's 8051 SLEIGH specification is written for decompilation, and it
# emulates arithmetic and bit addressing wrongly; see
# nix/patches/ghidra-8051.patch for the list.  Rebuilding Ghidra from source to
# change one language would take hours, so this derivation instead symlinks the
# stock installation, swaps in a patched copy of the 8051 language directory,
# and recompiles 8051.sla with Ghidra's own SLEIGH compiler.
#
# Ghidra finds its installation root from the canonical path of its bootstrap
# jar, Utility.jar.  Left as a symlink, that resolves back into the stock
# installation, which then loads the stock 8051 language; so Utility.jar is
# copied as a real file to anchor the root here.  Nothing reports it if a
# future Ghidra finds its root another way: it silently loads the stock 8051
# language, and the first sign is the `mcs51_flags` integration case failing.
{
  ghidra,
  jdk,
  runCommand,
}:

runCommand "${ghidra.name}-smallworld"
  {
    inherit (ghidra) version;
    passthru = { inherit (ghidra) meta; };
  }
  ''
    cp -rs ${ghidra} $out
    find $out -type d -exec chmod u+w {} +

    root=$out/lib/ghidra
    lang=$root/Ghidra/Processors/8051/data/languages
    for f in $lang/*; do
      if [ -L "$f" ]; then
        cp --remove-destination "$(readlink "$f")" "$f"
        chmod u+w "$f"
      fi
    done

    patch -p1 -d $root < ${./patches/ghidra-8051.patch}

    rm $lang/8051.sla
    HOME=$TMPDIR JAVA_HOME=${jdk} $root/support/sleigh $lang/8051.slaspec
    test -f $lang/8051.sla

    jar=$root/Ghidra/Framework/Utility/lib/Utility.jar
    cp --remove-destination "$(readlink "$jar")" "$jar"
  ''
