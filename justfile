set dotenv-load

mod cloud-config
mod ion

@_default:
  just --list --unsorted

build-and-insmod:
  #!/usr/bin/bash

  cd bp-module
  make clean
  make
  if lsmod | grep -q "^bp"; then
    rmmod -f bp
  fi
  insmod bp.ko