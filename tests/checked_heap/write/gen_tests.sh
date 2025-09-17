#!/usr/bin/env bash
#

for i in "AARCH64 LITTLE aarch64" "X86_64 LITTLE amd64" "ARM_V5T LITTLE armel" "ARM_V7A LITTLE armhf" "X86_32 LITTLE i386" "MIPS32 BIG mips" "MIPS64 BIG mips64" "MIPS64 LITTLE mips64el" "MIPS32 LITTLE mipsel" "POWERPC32 BIG ppc" "RISCV64 LITTLE riscv64"
do
  set -- $i
  cat write.template | sed 's/ARCH/'$1'/' | sed 's/ORDER/'$2'/' | sed 's/EMULATOR/UnicornEmulator/' >> write.$3.py
  cat write.template | sed 's/ARCH/'$1'/' | sed 's/ORDER/'$2'/' | sed 's/EMULATOR/PandaEmulator/' >> write.$3.panda.py
  cat write.template | sed 's/ARCH/'$1'/' | sed 's/ORDER/'$2'/' | sed 's/EMULATOR/AngrEmulator/' >> write.$3.angr.py
  cat write.template | sed 's/ARCH/'$1'/' | sed 's/ORDER/'$2'/' | sed 's/EMULATOR/GhidraEmulator/' >> write.$3.pcode.py
done

rm write.riscv64.panda.py
rm write.riscv64.py
rm write.mips64.py
rm write.mips64el.py
rm write.ppc.py
sed -i '' -e 's/, address=0x400000//' write.armel.*
sed -i '' -e 's/, address=0x400000//' write.mips64.*
sed -i '' -e 's/, address=0x400000//' write.mips64el.*
sed -i '' -e 's/, address=0x400000//' write.ppc.*
sed -i '' -e '/cpu.pc.set(entrypoint)/a\
cpu.t9.set(entrypoint)' write.mips64*
