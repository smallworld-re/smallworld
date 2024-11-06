SmallWorld's floating-point support is patchy due to patchy back-end support

| Arch/Subsystem   | angr | Panda | Unicorn | Notes                                   |
|------------------|------|-------|---------|-----------------------------------------|
| aarch64          | yes  |       | yes     |                                         |
| amd64 SSE        | yes  |       | yes     |                                         |
| armv5t           | n/a  | n/a   | n/a     | No FPU                                  |
| armv6x Adv. SIMD |      |       |         |                                         |
| armv7x VFPv2+    | yes  |       | no      | Capstone does not support VFPv2+        |
| i386 x87         | no   |       |         | Accessing x87 registers in angr is hard |
| i386 SSE         | yes  |       | yes     |                                         |
| mips             |      |       |         | Fails differently in both emulators     |
| mips64           |      |       | no      | Arch not supported in Unicorn           |
| ppc              |      |       | no      | Arch not supported in Unicorn           |
