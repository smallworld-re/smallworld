FROM ubuntu:24.04

ENV DEBIAN_FRONTEND noninteractive

# Update packages and package list
RUN apt update && \
    apt upgrade -y && \
    apt install -y wget patch

# Install kitware apt repo
RUN wget https://apt.kitware.com/kitware-archive.sh && \
    /bin/bash kitware-archive.sh

# Install apt dependencies
RUN apt install -y --no-install-recommends \
    git cmake ninja-build gperf ccache dfu-util \
    device-tree-compiler wget python3-dev \
    python3-pip python3-setuptools python3-tk \
    python3-wheel xz-utils file make gcc \
    gcc-multilib g++-multilib libsdl2-dev libmagic1

# Verify install success
RUN cmake --version && python3 --version && dtc --version

# venv setup
RUN apt install -y python3-venv && \
    python3 -m venv /zephyrproject/.venv
WORKDIR /zephyrproject
ENV PATH "/zephyrproject/.venv/bin:$PATH"

# Install west
RUN pip install west

# Pull zephyr source code
RUN west init /zephyrproject && \
    west update

# Export zephyr cmake package
RUN west zephyr-export

# Install python dependencies
RUN west packages pip --install

# Install Zephyr SDK
RUN cd zephyr && \
    west sdk install
