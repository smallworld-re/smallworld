#!/bin/bash

# Initialize Zephyr workspace
west init /zephyrproject
cd /zephyrproject
west update

# Build patched binary
patch /zephyrproject/zephyr/samples/net/sockets/echo_server/src/udp.c /opt/build_elf/udp.c.patch
west build -b qemu_cortex_a9 zephyr/samples/net/sockets/echo_server
