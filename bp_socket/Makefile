CC := gcc
CFLAGS := -Wall -Wextra -fPIC -g -I../include
LDFLAGS := -shared -ldl
SRC_FILES := $(wildcard *.c *.h)

.PHONY: all clean format

all: bp_interceptor.so

bp_interceptor.so: interceptor.c fd_table.c
	$(CC) $(CFLAGS) -o bp_interceptor.so interceptor.c fd_table.c $(LDFLAGS)

clean:
	rm -f bp_interceptor.so *.o