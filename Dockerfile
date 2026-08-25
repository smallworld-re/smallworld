FROM ghcr.io/actions/actions-runner:latest

USER root

# Install nix
RUN curl --proto '=https' --tlsv1.2 -sSf -L https://install.determinate.systems/nix | sh -s -- install --determinate --no-confirm
ENV PATH="${PATH}:/nix/var/nix/profiles/default/bin"
RUN echo "download-buffer-size = 536870912" >> /etc/nix/nix.conf

# Use cachix
RUN USER=root nix run nixpkgs#cachix -- use smallworld

# Copy smallworld
COPY . /opt/smallworld
WORKDIR /opt/smallworld
