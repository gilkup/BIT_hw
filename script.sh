#!/bin/bash

as ins_call.S -o ins_call.o
objcopy -O binary ins_call.o ins_call.bin
#objdump -d ins_call.o -w | grep -v "<" | grep ":" | cut -f2 | sed -e "s/ *$//g" | sed "s/ /,\(char\)0x/g" | sed "s/^/{\(char\)0x/g" | sed "s/$/},/g" | grep -v "i" > ins_call.bin.parsed
hexdump -v -e '"(unsigned char)0x" 1/1 "%02x" ","' ins_call.bin > ins_call.bin.parsed


make PIN_ROOT=../pin-3.2-81205-gcc-linux TEST_TOOL_ROOTS=rtn-translation-mt clean
make PIN_ROOT=../pin-3.2-81205-gcc-linux TEST_TOOL_ROOTS=rtn-translation-mt 
../pin-3.2-81205-gcc-linux/pin -t obj-intel64/rtn-translation-mt.so -- ./bzip2 -k -f given_files/input-long.txt
