SECTIONS {
  . = 600K;
  .text : { *(.text) *(.text.*) }
  PROVIDE (__end = .);
  ASSERT((__end < 640K), "Trampoline must be located in the area accessible by real mode")
}
ENTRY(_start)
