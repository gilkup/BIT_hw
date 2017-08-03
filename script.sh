#!/bin/bash

as inline_inst.S -o inline_inst.o
objcopy -O binary inline_inst.o inline_inst.bin
hexdump -v -e '"(unsigned char)0x" 1/1 "%02x" ","' inline_inst.bin > inline_inst.bin.parsed

as my_inst_read_aux.S -o my_inst_read_aux.o
objcopy -O binary my_inst_read_aux.o my_inst_read_aux.bin
hexdump -v -e '"(unsigned char)0x" 1/1 "%02x" ","' my_inst_read_aux.bin > my_inst_read_aux.bin.parsed



make PIN_ROOT=../pin-3.2-81205-gcc-linux TEST_TOOL_ROOTS=rtn-translation-mt clean
make PIN_ROOT=../pin-3.2-81205-gcc-linux TEST_TOOL_ROOTS=rtn-translation-mt 
../pin-3.2-81205-gcc-linux/pin -t obj-intel64/rtn-translation-mt.so -- ./bzip2 -k -f given_files/input-long.txt
