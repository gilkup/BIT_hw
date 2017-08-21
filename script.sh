#!/bin/bash

make PIN_ROOT=../pin-3.2-81205-gcc-linux clean
make PIN_ROOT=../pin-3.2-81205-gcc-linux
../pin-3.2-81205-gcc-linux/pin -t obj-intel64/project.so -- ./bzip2 -k -f given_files/input-long.txt
