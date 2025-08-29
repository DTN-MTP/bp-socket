CC := gcc
CFLAGS := -Wall -Wextra -Wpedantic -Wconversion -Wshadow -Wformat=2 -Wvla -fstack-protector-strong -D_FORTIFY_SOURCE=3 -fPIE -g -Wno-deprecated-declarations
LDFLAGS := -Wl,-z,relro,-z,now -pie -lpthread -lbp -lici -lm \
	$(shell pkg-config --libs libevent libnl-genl-3.0)

INCLUDES := $(shell pkg-config --cflags libnl-3.0)

EXEC := bp_daemon
SOURCES := $(wildcard *.c)
OBJECTS := $(SOURCES:.c=.o)

SRC_FILES := $(wildcard *.c *.h)

.PHONY: all release clean format

all: $(EXEC)

release: CFLAGS := -Wall -Wextra -Wpedantic -Wconversion -Wshadow -Wformat=2 -Wvla -fstack-protector-strong -D_FORTIFY_SOURCE=3 -fPIE -O3 -DNO_LOG -Wno-deprecated-declarations
release: all

$(EXEC): $(OBJECTS)
	$(CC) $(OBJECTS) -o $@ $(LDFLAGS)

%.o: %.c
	$(CC) -c $(CFLAGS) $(INCLUDES) $< -o $@

clean:
	rm -f $(EXEC) $(OBJECTS)

format:
	clang-format -i --style=file $(SRC_FILES)