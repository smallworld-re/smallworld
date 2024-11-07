# build: docker build . -t smallworld
#   run: docker run -it smallworld

FROM ubuntu:22.04

RUN apt update
RUN apt -y install git python3 python3-pip build-essential
RUN python3 -m pip install --upgrade pip

COPY ./ /opt/smallworld/

WORKDIR /opt/smallworld/tests
RUN apt -y install $(cat ./dependencies/apt.txt)
RUN apt -y install ./dependencies/*.deb
RUN python3 -m pip install ./dependencies/*.whl

RUN make

WORKDIR /opt/smallworld
RUN pip install -e .[development] -c constraints.txt
