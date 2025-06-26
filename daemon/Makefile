CC := gcc
CFLAGS := -Wall -Wno-deprecated-declarations -g
LDFLAGS := -lpthread -lbp -lici -lm \
	$(shell pkg-config --libs libevent libnl-genl-3.0)

INCLUDES := $(shell pkg-config --cflags libnl-3.0)

EXEC := bp_daemon
SOURCES := $(wildcard *.c)
OBJECTS := $(SOURCES:.c=.o)

SRC_FILES := $(wildcard *.c *.h)

.PHONY: all release clean format

all: $(EXEC)

release: CFLAGS := -Wall -Wno-deprecated-declarations -O3 -DNO_LOG
release: all

$(EXEC): $(OBJECTS)
	$(CC) $(OBJECTS) -o $@ $(LDFLAGS)

%.o: %.c
	$(CC) -c $(CFLAGS) $(INCLUDES) $< -o $@

clean:
	rm -f $(EXEC) $(OBJECTS)

format:
	clang-format -i --style=file $(SRC_FILES)