#!/bin/sh

set -e

SRCROOT=`pwd`/../../../

CFLAGS="-Wall -Wextra -ffreestanding -fno-stack-protector -O2 -g -fno-PIE -fno-PIC -m32 -mno-sse -DUNIBOOT_NO_BUILTIN -std=c11 "
CFLAGS+="-I$SRCROOT/include/ -I$SRCROOT"

gcc $CFLAGS -c -o uniboot32.o uniboot32.c
gcc $CFLAGS -c -o bootinfo.o ../../../hw/boot/bootinfo.c
ld -m elf_i386 -T linker.ld -s -o uniboot_trampoline32.elf uniboot32.o bootinfo.o
