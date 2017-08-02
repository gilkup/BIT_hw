#!/bin/bash

as inst_reads.S -o inst_reads.o
objcopy -O binary inst_reads.o inst_reads.bin
hexdump -v -e '"(unsigned char)0x" 1/1 "%02x" ","' inst_reads.bin > inst_reads.bin.parsed

as my_inst_read_aux.S -o my_inst_read_aux.o
objcopy -O binary my_inst_read_aux.o my_inst_read_aux.bin
hexdump -v -e '"(unsigned char)0x" 1/1 "%02x" ","' my_inst_read_aux.bin > my_inst_read_aux.bin.parsed



make PIN_ROOT=../pin-3.2-81205-gcc-linux TEST_TOOL_ROOTS=rtn-translation-mt clean
make PIN_ROOT=../pin-3.2-81205-gcc-linux TEST_TOOL_ROOTS=rtn-translation-mt 
../pin-3.2-81205-gcc-linux/pin -t obj-intel64/rtn-translation-mt.so -- ./bzip2 -k -f given_files/input-long.txt
