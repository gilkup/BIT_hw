#!/bin/bash

as ins_call.S -o ins_call.o
objcopy -O binary ins_call.o ins_call.bin
hexdump -v -e '"(unsigned char)0x" 1/1 "%02x" ","' ins_call.bin > ins_call.bin.parsed

as my_inst_read_aux.S -o my_inst_read_aux.o
objcopy -O binary my_inst_read_aux.o my_inst_read_aux.bin
hexdump -v -e '"(unsigned char)0x" 1/1 "%02x" ","' my_inst_read_aux.bin > my_inst_read_aux.bin.parsed



make PIN_ROOT=../pin-3.2-81205-gcc-linux TEST_TOOL_ROOTS=rtn-translation-mt clean
make PIN_ROOT=../pin-3.2-81205-gcc-linux TEST_TOOL_ROOTS=rtn-translation-mt 
../pin-3.2-81205-gcc-linux/pin -t obj-intel64/rtn-translation-mt.so -- ./bzip2 -k -f given_files/input-long.txt
