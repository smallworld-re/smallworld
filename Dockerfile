# make sure you build as follows
#
# First, clone smallworld
# % git clone git@github.com:smallworld-re/smallworld.git
# Second, build docker container from where you are as follows
# % docker build  . -t smallworld -f ./smallworld/Dockerfile

FROM ubuntu:22.04

RUN apt-get update
RUN apt -y  install git pip nasm
COPY smallworld smallworld
WORKDIR /smallworld/tests
RUN make
WORKDIR /smallworld
RUN pip install -e .[development] -c constraints.txt
