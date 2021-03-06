/*
 * Uniboot Option ROM
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright Anatol Pomozov, 2018
 * Copyright Novell Inc, 2009
 *   Authors: Alexander Graf <agraf@suse.de>
 */

#include "optionrom.h"

#define BOOT_ROM_PRODUCT "uniboot loader"

#define GS_PROT_JUMP		0
#define GS_GDT_DESC		6

#define MEMINFO_INFO_ADDR (580 * 1024)

BOOT_ROM_START

run_uniboot:
	cli
	cld

	mov		%cs, %eax
	shl		$0x4, %eax

	/* set up a long jump descriptor that is PC relative */

	/* move stack memory to %gs */
	mov		%ss, %ecx
	shl		$0x4, %ecx
	mov		%esp, %ebx
	add		%ebx, %ecx
	sub		$0x20, %ecx
	sub		$0x30, %esp
	shr		$0x4, %ecx
	mov		%cx, %gs

	/* now push the indirect jump descriptor there */
	mov		(prot_jump), %ebx
	add		%eax, %ebx
	movl		%ebx, %gs:GS_PROT_JUMP
	mov		$8, %bx
	movw		%bx, %gs:GS_PROT_JUMP + 4

	/* fix the gdt descriptor to be PC relative */
	movw		(gdt_desc), %bx
	movw		%bx, %gs:GS_GDT_DESC
	movl		(gdt_desc+2), %ebx
	add		%eax, %ebx
	movl		%ebx, %gs:GS_GDT_DESC + 2

	/* ES = mmap_addr
	 * %es:0 (4 bytes) - size of memmap in bytes
	 * 4 + 20*n  - mmap entry number n
	 */
	mov 	$MEMINFO_INFO_ADDR, %eax
	shr		$4, %eax
	mov		%ax, %es

	/* Initialize uniboot mmap structs using int 0x15(e820) */
	xor		%ebx, %ebx
	/* Start storing mmap data at %es:4 */
	mov		$4, %edi

mmap_loop:
	/* buffer size available for mmap info */
	movl	$10240, %ecx
	sub		%edi,%ecx

	/* e820 */
	mov		$0xe820, %eax
	/* 'SMAP' magic */
	mov		$0x534d4150, %edx
	int		$0x15

mmap_check_entry:
	/* Error or last entry already done? */
	jb		mmap_done

	add		%ecx, %edi

	/* Continuation value 0 means last entry */
	test	%ebx, %ebx
	jnz		mmap_loop

mmap_done:
	/* save size of used mmap area */
	movl %edi, %es:0

real_to_prot:
	/* Load the GDT before going into protected mode */
lgdt:
	data32 lgdt	%gs:GS_GDT_DESC

	/* get us to protected mode now */
	movl		$1, %eax
	movl		%eax, %cr0

	/* the LJMP sets CS for us and gets us to 32-bit */
ljmp:
	data32 ljmp	*%gs:GS_PROT_JUMP

prot_mode:
.code32

	/* initialize all other segments */
	movl		$0x10, %eax
	movl		%eax, %ss
	movl		%eax, %ds
	movl		%eax, %es
	movl		%eax, %fs
	movl		%eax, %gs

	/* Read the unicycle application code into RAM */
	read_fw_blob(FW_CFG_KERNEL)

	/* Read the bootinfo data into RAM */
	read_fw_blob(FW_CFG_INITRD)

	/* Read the trampoline code into RAM */
	read_fw_blob(FW_CFG_SETUP)

	/* Jump off to the trampoline */
	read_fw		FW_CFG_SETUP_ENTRY
	mov		%eax, %ecx

ljmp2:
	jmp		*%ecx

/* Variables */
.align 4, 0
prot_jump:
	.long prot_mode
	.short 8

.align 4, 0
gdt:
	/* 0x00 */
.byte	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	/* 0x08: code segment (base=0, limit=0xfffff, type=32bit code exec/read, DPL=0, 4k) */
.byte	0xff, 0xff, 0x00, 0x00, 0x00, 0x9a, 0xcf, 0x00
	/* 0x10: data segment (base=0, limit=0xfffff, type=32bit data read/write, DPL=0, 4k) */
.byte	0xff, 0xff, 0x00, 0x00, 0x00, 0x92, 0xcf, 0x00

gdt_desc:
.short	(3 * 8) - 1
.long	gdt

BOOT_ROM_END
