#!/bin/bash

# Build Docker image
docker build -t smallworld-zephyr-sdk -f ./build_elf/zephyr_build.dockerfile .

# Create new container for build
docker rm smallworld-zephyr-build
docker run --name smallworld-zephyr-build -v ./build_elf:/opt/build_elf --entrypoint "/opt/build_elf/entrypoint.sh" smallworld-zephyr-sdk

# Extract zephyr.elf
docker cp smallworld-zephyr-build:/zephyrproject/build/zephyr/zephyr.elf ./zephyr.elf

# Remove container
docker rm smallworld-zephyr-build
