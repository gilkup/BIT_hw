#!/bin/bash

make PIN_ROOT=../pin-3.2-81205-gcc-linux
../pin-3.2-81205-gcc-linux/pin -t obj-intel64/ex.so -prof -- ./bzip2


#rm  obj-intel64/ex3.so
#mkdir obj-intel64
#rm -f rtn-output.txt

#make PIN_ROOT=~/pin_hw/pin-3.2-81205-gcc-linux/
#make 
#cp given_files/clean/input.txt given_files/
#rm given_files/input.txt.bz2
#../../../pin -t obj-intel64/ex3.so --  given_files/bzip2 -k -f given_files/input.txt
