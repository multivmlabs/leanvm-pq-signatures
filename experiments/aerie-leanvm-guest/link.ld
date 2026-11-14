ENTRY(_start)
MEMORY {
  TEXT (rx)   : ORIGIN = 0x10000000, LENGTH = 256M
  ADVICE (rw) : ORIGIN = 0x20000000, LENGTH = 512M
  RAM (rw)    : ORIGIN = 0x40000000, LENGTH = 16M
}
SECTIONS {
  .text : { KEEP(*(.text._start)) *(.text .text.*) } > TEXT
  .data : { *(.rodata .rodata.* .srodata .srodata.*) *(.data .data.* .sdata .sdata.*) *(.got .got.*) } > RAM
  .bss (NOLOAD) : { *(.bss .bss.* .sbss .sbss.*) } > RAM
  . = ALIGN(16);
  __heap_start = .;
  __heap_end = ORIGIN(RAM) + LENGTH(RAM) - 1M;
  __stack_top = ORIGIN(RAM) + LENGTH(RAM);
  __advice = ORIGIN(ADVICE);
  __advice_top = ORIGIN(ADVICE) + (DEFINED(__advice_bytes) ? __advice_bytes : 64K);
  /DISCARD/ : { *(.eh_frame .eh_frame_hdr .comment .riscv.attributes) }
}
