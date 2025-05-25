#!/usr/bin/bash

cd src/kernel
make clean
make
if lsmod | grep -q "^bp"; then
rmmod -f bp
fi
insmod bp.ko