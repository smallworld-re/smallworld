# build: docker build . -t smallworld
#   run: docker run -it smallworld

# Inherit from panda.
FROM pandare/panda:latest

RUN apt update
RUN apt -y install build-essential curl

# This is a disaster of a hack to get python3.10 in Ubuntu 20.04
RUN apt -y install software-properties-common
RUN add-apt-repository ppa:deadsnakes/ppa
RUN apt update
RUN apt search python3.10
RUN apt -y install git python3.10 python3.10-venv python3.10-dev
RUN rm -f /usr/bin/python3
RUN ln -s python3.10 /usr/bin/python3

# And another disaster of a hack to install pip for python3.10
RUN curl -sS https://bootstrap.pypa.io/get-pip.py | python3

# Enable the venv, and upgrade pip
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
RUN python3 -m pip install --upgrade pip

# Copy Panda out of python3.8 and into the venv
RUN mkdir /opt/whl
WORKDIR /opt/whl
RUN python3.8 -m pip wheel pandare
RUN python3 -m pip install pandare*.whl

# Fix bug in Panda; it needs this file for mips64 to work
RUN touch /usr/local/lib/python3.8/dist-packages/pandare/data/pc-bios/mips_bios.bin

# Install smallworld
COPY ./ /opt/smallworld/

WORKDIR /opt/smallworld/tests
RUN apt -y install $(cat ./dependencies/apt.txt)
RUN apt -y install ./dependencies/*.deb
RUN python3 -m pip install ./dependencies/*.whl

RUN make

WORKDIR /opt/smallworld
RUN python3 -m pip install -e .[development] -c constraints.txt
