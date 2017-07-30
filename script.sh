#!/bin/bash

make PIN_ROOT=../pin-3.2-81205-gcc-linux
../pin-3.2-81205-gcc-linux/pin -t obj-intel64/ex.so -prof -- ./bzip2 -k -f given_files/input.txt
../pin-3.2-81205-gcc-linux/pin -t obj-intel64/rtn-translation-mt.so -- ./bzip2 -k -f given_files/input-long.txt
