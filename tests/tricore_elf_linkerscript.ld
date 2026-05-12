ENTRY(_start)

PHDRS
{
  all PT_LOAD FILEHDR PHDRS FLAGS(7);
}

SECTIONS
{
  . = 0x1000 + SIZEOF_HEADERS;

  .text : {
    *(.text .text.*)
  } :all

  .rodata : {
    *(.rodata .rodata.*)
    *(.sdata2 .sdata2.*)
    *(.zrodata .zrodata.*)
  } :all

  .data : {
    *(.data .data.*)
    *(.sdata .sdata.*)
    *(.zdata .zdata.*)
  } :all

  .bss : {
    *(.bss .bss.*)
    *(.sbss .sbss.*)
    *(.zbss .zbss.*)
    *(COMMON)
  } :all
}
