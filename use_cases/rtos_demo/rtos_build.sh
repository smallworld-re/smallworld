#!/bin/bash

# Create new container and build
docker rm smallworld-zephyr-build
docker run --name smallworld-zephyr-build -v ./build_elf:/opt/build_elf --entrypoint "/opt/build_elf/entrypoint.sh" zephyrprojectrtos/ci

# Extract zephyr.elf
docker cp smallworld-zephyr-build:/zephyrproject/build/zephyr/zephyr.elf ./zephyr.elf

# Remove container
docker rm smallworld-zephyr-build
