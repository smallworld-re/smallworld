#!/usr/bin/env bash
#

for i in "AARCH64 LITTLE aarch64" "X86_64 LITTLE amd64" "ARM_V6M LITTLE armel" "ARM_V7A LITTLE armhf" "X86_32 LITTLE i386" "MIPS32 BIG mips" "MIPS64 BIG mips64" "MIPS64 LITTLE mips64el" "MIPS32 LITTLE mipsel" "POWERPC32 BIG ppc" "RISCV64 LITTLE riscv64"
do
  set -- $i
  cat double_free.template | sed 's/ARCH/'$1'/' | sed 's/ORDER/'$2'/' | sed 's/EMULATOR/UnicornEmulator/' > double_free.$3.py
  cat double_free.template | sed 's/ARCH/'$1'/' | sed 's/ORDER/'$2'/' | sed 's/EMULATOR/PandaEmulator/' > double_free.$3.panda.py
  cat double_free.template | sed 's/ARCH/'$1'/' | sed 's/ORDER/'$2'/' | sed 's/EMULATOR/AngrEmulator/' > double_free.$3.angr.py
  cat double_free.template | sed 's/ARCH/'$1'/' | sed 's/ORDER/'$2'/' | sed 's/EMULATOR/GhidraEmulator/' > double_free.$3.pcode.py
done

rm double_free.riscv64.panda.py
rm double_free.riscv64.py
rm double_free.mips64.py
rm double_free.mips64el.py
rm double_free.ppc.py

sed -i '' -e 's/, address=0x400000//' double_free.armel.*
sed -i '' -e 's/, address=0x400000//' double_free.mips.*
sed -i '' -e 's/, address=0x400000//' double_free.mipsel.*
sed -i '' -e 's/, address=0x400000//' double_free.mips64.*
sed -i '' -e 's/, address=0x400000//' double_free.mips64el.*
sed -i '' -e 's/, address=0x400000//' double_free.ppc.*
sed -i '' -e '/cpu.pc.set(entrypoint)/a\
cpu.t9.set(entrypoint)' double_free.mips*
