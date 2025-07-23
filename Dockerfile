ARG DOCKER_REGISTRY=harbor.harbor.svc.cluster.local
FROM ${DOCKER_REGISTRY}/smallworld/smallworld_testdeps:latest

# Install smallworld
COPY ./ /opt/smallworld/

WORKDIR /opt/smallworld/tests
RUN make -j$(nproc)
WORKDIR /opt/smallworld/tests/elf_core
RUN make -j$(nproc)

WORKDIR /opt/smallworld
RUN python3 -m pip install -e .[development] -c constraints.txt
