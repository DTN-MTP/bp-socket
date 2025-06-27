bp-objs := bp_genl.o af_bp.o bp_module.o eid.o
obj-m += bp.o

KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

SRC_FILES := $(wildcard *.c *.h)

.PHONY: all clean sparse

all:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

sparse:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules C=1 CHECK=sparse

format:
	clang-format -i --style=file $(SRC_FILES)