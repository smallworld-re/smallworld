#!/bin/bash
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
export CODE_ROOT="$HOME/code"
export GHIDRA_INSTALL_DIR="$CODE_ROOT/ghidra/ghidra_11.3.2_PUBLIC"
export NEEDRESTART_MODE=a

mkdir -p "$CODE_ROOT"

# -------- SYSTEM SETUP -------- #
sudo apt-get update -y
sudo NEEDRESTART_MODE=a \
apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    build-essential \
    python3-dev \
    automake \
    cmake \
    git \
    flex \
    bison \
    libglib2.0-dev \
    libpixman-1-dev \
    python3-setuptools \
    cargo \
    libgtk-3-dev \
    lld-14 \
    llvm-14 \
    llvm-14-dev \
    clang-14 \
    python3-venv \
    nasm \
    curl \
    wget \
    unzip \
    gnupg \
    software-properties-common

# -------- CROSS-COMPILERS AND DEV TOOLS -------- #
# TODO note lx106 and i686 are additions
GCC_VER=$(gcc -dumpversion | cut -d. -f1)
sudo NEEDRESTART_MODE=a \
apt-get install -y \
    gcc-${GCC_VER}-plugin-dev \
    libstdc++-${GCC_VER}-dev \
    openjdk-21-jdk \
    gcc-arm-linux-gnueabi \
    gcc-aarch64-linux-gnu \
    gcc-arm-linux-gnueabihf \
    gcc-mips-linux-gnu \
    gcc-mips64-linux-gnuabi64 \
    gcc-mipsel-linux-gnu \
    gcc-mips64el-linux-gnuabi64 \
    gcc-powerpc-linux-gnu \
    gcc-powerpc64-linux-gnu \
    gcc-riscv64-linux-gnu \
    gcc-sparc64-linux-gnu \
    gcc-xtensa-lx106 \
    gcc-i686-linux-gnu \
    gcc-mingw-w64 \
    qemu-user \
    gdb-multiarch

sudo apt-get clean

# -------- PYTHON VENV -------- #
python3 -m venv "$CODE_ROOT/venv"
source "$CODE_ROOT/venv/bin/activate"
pip install --upgrade pip wheel

# -------- AFL++ -------- #
if python3 -c "import unicornafl" 2>/dev/null; then
  echo "✔ AFL++ already installed, skipping."
else
  echo "Installing AFL++..."
  mkdir -p "$CODE_ROOT/afl" && cd "$CODE_ROOT/afl"
  git clone https://github.com/AFLplusplus/AFLplusplus
  cd AFLplusplus
  git checkout f590973387ee04d6c7ef016d5111313f9f4945b8
  export DEBUG=1 NO_NYX=1 INTROSPECTION=1 NO_CORESIGHT=1
  make -j"$(nproc)" binary-only
  sudo make install
  cd unicorn_mode/unicornafl/bindings/python
  python3 setup.py install
  python3 -c "import unicornafl"
  cd "$CODE_ROOT" && rm -rf afl
fi

# -------- PANDA -------- #
if python3 -c "import pandare" 2>/dev/null; then
  echo "✔ PANDA already installed, skipping."
else
  echo "Installing PANDA..."
  mkdir -p "$CODE_ROOT/panda" && cd "$CODE_ROOT/panda"
  wget https://github.com/panda-re/panda/releases/download/v1.8.57/pandare_22.04.deb
  wget https://github.com/panda-re/panda/releases/download/v1.8.57/pandare-1.8.57-py3-none-any.whl
  sudo NEEDRESTART_MODE=a apt-get -y install ./pandare_22.04.deb
  rm pandare_22.04.deb
  python3 -m pip install pandare-1.8.57-py3-none-any.whl
  python3 -c "import pandare"
  # Panda needs these two files to be created to fix particular bugs
  sudo touch /usr/local/share/panda/mips_bios.bin
  sudo touch /usr/local/share/panda/mipsel_bios.bin
fi

# -------- GHIDRA -------- #
if python3 -c "import pyghidra; pyghidra.start()" &>/dev/null; then
  echo "✔ Ghidra & PyGhidra already installed, skipping."
else
  echo "Installing Ghidra..."
  mkdir -p "$CODE_ROOT/ghidra" && cd "$CODE_ROOT/ghidra"
  wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.3.2_build/ghidra_11.3.2_PUBLIC_20250415.zip
  unzip ghidra_11.3.2_PUBLIC_20250415.zip
  python3 -m pip install --no-index -f "$GHIDRA_INSTALL_DIR/Ghidra/Features/PyGhidra/pypkg/dist" pyghidra
  python3 -c "import pyghidra; pyghidra.start()"
fi

# -------- SMALLWORLD APT DEPS -------- #
APT_DEP_FILE="$CODE_ROOT/smallworld/dependencies/apt.txt"
if [[ -f "$APT_DEP_FILE" ]]; then
  echo "Installing smallworld APT dependencies..."
  xargs -a "$APT_DEP_FILE" sudo NEEDRESTART_MODE=a apt-get install -y
  sudo apt-get clean
fi

# -------- SMALLWORLD -------- #
echo "Installing SmallWorld..."
rm -rf "$CODE_ROOT/smallworld"
git clone https://github.com/smallworld-re/smallworld.git "$CODE_ROOT/smallworld"


# -------- SMALLWORLD PYTHON INSTALL -------- #
cd "$CODE_ROOT/smallworld"
if [[ -f "constraints.txt" ]]; then
  python3 -m pip install -e .[development] -c constraints.txt
else
  python3 -m pip install -e .[development]
fi

# -------- SMALLWORLD BUILD -------- #
ulimit -c unlimited
cd "$CODE_ROOT/smallworld/tests"
make -j"$(nproc)"
cd elf_core
make -j"$(nproc)"

# -------- FINAL CHECK -------- #
echo "Final sanity check:"
python3 -c "import unicornafl, pandare, pyghidra; print('✔ All major components imported successfully.')"
