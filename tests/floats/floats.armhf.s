    .arch armv7-a
	.fpu vfpv3-d16
    .eabi_attribute 28, 1
	.eabi_attribute 20, 1
	.eabi_attribute 21, 1
	.eabi_attribute 23, 3
	.eabi_attribute 24, 1
	.eabi_attribute 25, 1
	.eabi_attribute 26, 2
	.eabi_attribute 30, 6
	.eabi_attribute 34, 0
	.eabi_attribute 18, 4
    .text
    .syntax unified
    .arm
test:
    vadd.f64 d0,d0,d1
