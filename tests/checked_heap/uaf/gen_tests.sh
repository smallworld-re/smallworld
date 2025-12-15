#!/usr/bin/env bash
#

for i in "AARCH64 LITTLE aarch64" "X86_64 LITTLE amd64" "ARM_V6M LITTLE armel" "ARM_V7A LITTLE armhf" "X86_32 LITTLE i386" "MIPS32 BIG mips" "MIPS64 BIG mips64" "MIPS64 LITTLE mips64el" "MIPS32 LITTLE mipsel" "POWERPC32 BIG ppc" "RISCV64 LITTLE riscv64"
do
  set -- $i
  cat uaf.template | sed 's/ARCH/'$1'/' | sed 's/ORDER/'$2'/' | sed 's/EMULATOR/UnicornEmulator/' > uaf.$3.py
  cat uaf.template | sed 's/ARCH/'$1'/' | sed 's/ORDER/'$2'/' | sed 's/EMULATOR/PandaEmulator/' > uaf.$3.panda.py
  cat uaf.template | sed 's/ARCH/'$1'/' | sed 's/ORDER/'$2'/' | sed 's/EMULATOR/AngrEmulator/' > uaf.$3.angr.py
  cat uaf.template | sed 's/ARCH/'$1'/' | sed 's/ORDER/'$2'/' | sed 's/EMULATOR/GhidraEmulator/' > uaf.$3.pcode.py
done

rm uaf.riscv64.panda.py
rm uaf.riscv64.py
rm uaf.mips64.py
rm uaf.mips64el.py
rm uaf.ppc.py
sed -i '' -e 's/, address=0x400000//' uaf.armel.*
sed -i '' -e 's/, address=0x400000//' uaf.mips64.*
sed -i '' -e 's/, address=0x400000//' uaf.mips64el.*
sed -i '' -e 's/, address=0x400000//' uaf.ppc.*
sed -i '' -e 's/, address=0x400000//' uaf.mipsel.*
sed -i '' -e 's/, address=0x400000//' uaf.mips.*
sed -i '' -e '/cpu.pc.set(entrypoint)/a\
cpu.t9.set(entrypoint)' uaf.mips*
