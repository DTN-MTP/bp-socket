.PHONY: all bp_socket daemon clean format check-format

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
