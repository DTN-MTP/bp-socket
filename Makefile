.PHONY: all bp_socket daemon clean format install

all: bp_socket daemon

bp_socket:
	$(MAKE) -C bp_socket

daemon:
	$(MAKE) -C daemon

clean:
	$(MAKE) -C bp_socket clean
	$(MAKE) -C daemon clean

format:
	$(MAKE) -C bp_socket format
	$(MAKE) -C daemon format

install:
	install -d /usr/local/include
	install -m 644 include/bp_socket.h /usr/local/include/
	$(MAKE) -C daemon install
	$(MAKE) -C bp_socket install