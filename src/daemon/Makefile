CC = gcc
CXXFLAGS=-Wall -Wno-deprecated-declarations
CXX_DEBUG_FLAGS=-g
CXX_RELEASE_FLAGS=-O3 -DNO_LOG
CXX_CLIENTAUTH_FLAGS= -g -DCLIENT_AUTH
 
EXEC = bp_daemon
SOURCES = $(wildcard *.c)
OBJECTS = $(SOURCES:.c=.o)
STD_INCLUDES = `pkg-config --cflags libnl-3.0`
NEW_INCLUDES = \
	`pkg-config --cflags libnl-3.0` \
	-Ilibevent/include
LIBS = 	-lpthread \
	-lbp -lici \
	`pkg-config --libs \
		libevent \
		libnl-genl-3.0` \
	-lm
LIBS_EX = \
	-Llibevent/lib \
	-Wl,-rpath \
	-Wl,libevent/lib \
	-Wl,-rpath \
	-lpthread \
	`pkg-config --libs \
		libnl-genl-3.0 \
		libnotify \
		`
  
INCLUDES= \
	`pkg-config --cflags libnotify`

BASHRC=$(HOME)/.bashrc

.PHONY: clean

all: CXXFLAGS+=$(CXX_DEBUG_FLAGS)
all: INCLUDES=$(STD_INCLUDES)
all: $(EXEC)

release: CXXFLAGS+=$(CXX_RELEASE_FLAGS)
release: INCLUDES+=$(STD_INCLUDES)
release: $(EXEC)

# Main target
$(EXEC): $(OBJECTS)
	$(CC) $(OBJECTS) -o $(EXEC) $(LIBS)
 
# To obtain object files
%.o: %.c
	$(CC) -c $(CXXFLAGS) $< $(INCLUDES) -o $@
 
# To remove generated files
clean:
	rm -f $(EXEC) $(OBJECTS)
