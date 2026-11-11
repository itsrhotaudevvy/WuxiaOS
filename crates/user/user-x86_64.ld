/* Fixed-address layout for the bootstrap user program.
 * Base 0x8000000000 is 512 GiB, inside the lower-half user range and PML4 slot 1.
 */
ENTRY(_start)

SECTIONS
{
    . = 0x8000000000;

    .text : ALIGN(4096)
    {
        *(.text._start)
        *(.text .text.*)
    }

    .rodata : ALIGN(4096)
    {
        *(.rodata .rodata.*)
    }

    .data : ALIGN(4096)
    {
        *(.data .data.*)
        *(.got .got.plt)
    }

    .bss : ALIGN(4096)
    {
        *(.bss .bss.*)
        *(COMMON)
    }

    /DISCARD/ :
    {
        *(.comment)
        *(.note .note.*)
        *(.eh_frame .eh_frame_hdr)
        *(.gcc_except_table*)
    }
}
