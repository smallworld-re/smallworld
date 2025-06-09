FROM docker-registry.docker-registry.svc.cluster.local:5000/smallworld/smallworld_deps:latest

# Install smallworld
COPY ./ /opt/smallworld/

WORKDIR /opt/smallworld/tests
RUN apt -y install $(cat ./dependencies/apt.txt)

RUN make -j$(nproc)

WORKDIR /opt/smallworld
RUN python3 -m pip install -e .[development] -c constraints.txt
