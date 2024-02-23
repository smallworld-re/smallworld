# build: docker build . -t smallworld
#   run: docker run -it smallworld

FROM ubuntu:22.04

RUN apt update
RUN apt -y install git pip nasm

COPY ./ /opt/smallworld/

WORKDIR /opt/smallworld/tests
RUN make

WORKDIR /opt/smallworld
RUN pip install -e .[development] -c constraints.txt
