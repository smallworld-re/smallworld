FROM ghcr.io/actions/actions-runner:latest

USER root

# Install cross-compilers
RUN apt-get update -y
RUN apt-get install -y build-essential xz-utils wget make nasm binutils-arm-linux-gnueabi binutils-arm-linux-gnueabihf binutils-i686-linux-gnu binutils-mips-linux-gnu binutils-mipsel-linux-gnu binutils-mips64-linux-gnuabi64 binutils-mips64el-linux-gnuabi64 binutils-powerpc-linux-gnu binutils-powerpc64-linux-gnu binutils-riscv64-linux-gnu binutils-xtensa-lx106 gcc-arm-linux-gnueabi gcc-arm-linux-gnueabihf gcc-i686-linux-gnu gcc-mips-linux-gnu gcc-mipsel-linux-gnu gcc-mips64-linux-gnuabi64 gcc-mips64el-linux-gnuabi64 gcc-powerpc-linux-gnu gcc-powerpc64-linux-gnu gcc-riscv64-linux-gnu gcc-mingw-w64 qemu-user gdb-multiarch
RUN wget https://github.com/smallworld-re/buildtools/releases/latest/download/buildtools-loongarch64-linux-gnu.deb && apt-get install ./buildtools-*.deb

# Install nix
RUN curl --proto '=https' --tlsv1.2 -sSf -L https://install.determinate.systems/nix | sh -s -- install --determinate --no-confirm
ENV PATH="${PATH}:/nix/var/nix/profiles/default/bin"
RUN echo "download-buffer-size = 536870912" >> /etc/nix/nix.conf

# Use cachix
RUN USER=root nix run nixpkgs#cachix -- use smallworld

# Copy smallworld
COPY . /opt/smallworld
WORKDIR /opt/smallworld
