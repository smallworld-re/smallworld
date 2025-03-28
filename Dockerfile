# build: docker build . -t smallworld
#   run: docker run -it smallworld

FROM ubuntu:22.04

RUN apt update
RUN apt -y install apt -y python3 python3-pip build-essential python3-dev automake cmake git flex bison libglib2.0-dev libpixman-1-dev python3-setuptools cargo libgtk-3-dev lld-14 llvm-14 llvm-14-dev clang-14 git python3-venv nasm curl wget
RUN apt -y install gcc-$(gcc --version|head -n1|sed 's/\..*//'|sed 's/.* //')-plugin-dev libstdc++-$(gcc --version|head -n1|sed 's/\..*//'|sed 's/.* //')-dev

# Enable the venv
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
RUN pip3 install wheel

WORKDIR /opt/afl
RUN git clone https://github.com/AFLplusplus/AFLplusplus
WORKDIR /opt/afl/AFLplusplus
RUN git checkout f590973387ee04d6c7ef016d5111313f9f4945b8
ENV DEBUG=1
ENV NO_NYX=1
ENV INTROSPECTION=1
ENV NO_CORESIGHT=1
RUN make binary-only
RUN make install

# We need to reinstall in our venv
WORKDIR /opt/afl/AFLplusplus/unicorn_mode/unicornafl/bindings/python
RUN python3 setup.py install
RUN python3 -c "import unicornafl"

WORKDIR /opt/panda
RUN wget 'https://github.com/panda-re/panda/releases/download/v1.8.57/pandare_22.04.deb'
RUN wget 'https://github.com/panda-re/panda/releases/download/v1.8.57/pandare-1.8.57-py3-none-any.whl'
RUN apt -y install ./pandare_22.04.deb
RUN python3 -m pip install pandare-1.8.57-py3-none-any.whl
RUN python3 -c "import pandare"

# Fix bug in Panda; it needs this file for mips64 to work
RUN touch /usr/local/share/panda/mips_bios.bin

# Install smallworld
COPY ./ /opt/smallworld/

WORKDIR /opt/smallworld/tests
RUN apt -y install $(cat ./dependencies/apt.txt)

RUN make

WORKDIR /opt/smallworld
RUN python3 -m pip install -e .[development] -c constraints.txt
