#!/bin/bash

rm  obj-intel64/ex2.so
mkdir obj-intel64
#rm rtn-output.txt
make PIN_ROOT=~/pin_hw/pin-3.2-81205-gcc-linux/

#cp given_files/clean/input.txt given_files/
#rm given_files/input.txt.bz2
../../../pin -t obj-intel64/ex2.so --  given_files/bzip2 -k -f given_files/input.txt
