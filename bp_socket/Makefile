bp-objs := bp_genl.o af_bp.o bp_module.o eid.o
obj-m += bp.o

KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

SRC_FILES := $(wildcard *.c *.h)

.PHONY: all clean format

all:
	make -C $(KDIR) M=$(PWD) modules

clean:
	make -C $(KDIR) M=$(PWD) clean

format:
	clang-format -i --style=file $(SRC_FILES)