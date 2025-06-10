FROM docker-registry.docker-registry.svc.cluster.local:5000/smallworld/smallworld_testdeps:latest

# Install smallworld
COPY ./ /opt/smallworld/

WORKDIR /opt/smallworld/tests
RUN make -j$(nproc)

WORKDIR /opt/smallworld
RUN python3 -m pip install -e .[development] -c constraints.txt
