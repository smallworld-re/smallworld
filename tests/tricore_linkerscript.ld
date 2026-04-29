ENTRY(_start)

SECTIONS
{
  . = 0x1000;

  .text : {
    *(.text .text.*)
  }

  .rodata : {
    *(.rodata .rodata.*)
    *(.sdata2 .sdata2.*)
    *(.zrodata .zrodata.*)
  }

  .data : {
    *(.data .data.*)
    *(.sdata .sdata.*)
    *(.zdata .zdata.*)
  }

  .bss : {
    *(.bss .bss.*)
    *(.sbss .sbss.*)
    *(.zbss .zbss.*)
    *(COMMON)
  }
}
