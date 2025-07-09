CC = gcc
CFLAGS = -Wall -g
LDFLAGS = -lbp -lici -lm 

all: sender receiver

sender: sender.c
	$(CC) $(CFLAGS) -o sender sender.c $(LDFLAGS)

receiver: receiver.c
	$(CC) $(CFLAGS) -o receiver receiver.c $(LDFLAGS)

clean:
	rm -f sender receiver

format:
	clang-format -i sender.c receiver.c

test:
	./inject_bundles.sh
