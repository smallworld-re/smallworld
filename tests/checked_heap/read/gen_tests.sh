#!/usr/bin/env bash
#

for i in "AARCH64 LITTLE aarch64" "X86_64 LITTLE amd64" "ARM_V5T LITTLE armel" "ARM_V7A LITTLE armhf" "X86_32 LITTLE i386" "MIPS32 BIG mips" "MIPS64 BIG mips64" "MIPS64 LITTLE mips64el" "MIPS32 LITTLE mipsel" "POWERPC32 BIG ppc" "RISCV64 LITTLE riscv64"
do
  set -- $i
  cat read.template | sed 's/ARCH/'$1'/' | sed 's/ORDER/'$2'/' | sed 's/EMULATOR/UnicornEmulator/' >> read.$3.py
  cat read.template | sed 's/ARCH/'$1'/' | sed 's/ORDER/'$2'/' | sed 's/EMULATOR/PandaEmulator/' >> read.$3.panda.py
  cat read.template | sed 's/ARCH/'$1'/' | sed 's/ORDER/'$2'/' | sed 's/EMULATOR/AngrEmulator/' >> read.$3.angr.py
  cat read.template | sed 's/ARCH/'$1'/' | sed 's/ORDER/'$2'/' | sed 's/EMULATOR/GhidraEmulator/' >> read.$3.pcode.py
done

rm read.riscv64.panda.py
rm read.riscv64.py
rm read.mips64.py
rm read.mips64el.py
rm read.ppc.py
sed -i '' -e 's/, address=0x400000//' read.armel.*
sed -i '' -e 's/, address=0x400000//' read.mips64.*
sed -i '' -e 's/, address=0x400000//' read.mips64el.*
sed -i '' -e 's/, address=0x400000//' read.ppc.*
sed -i '' -e '/cpu.pc.set(entrypoint)/a\
cpu.t9.set(entrypoint)' read.mips64*
