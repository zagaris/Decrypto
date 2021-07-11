CC = gcc
CFLAGS =  -Wall -pedantic -g
LIBSSL = -lssl -lcrypto

TARGETS = server client

all: $(TARGETS)

server: server.c crypto.h crypto.c
	$(CC) $(CFLAGS) server.c crypto.h crypto.c -o server $(LIBSSL)

client: client.c crypto.h crypto.c
	$(CC) $(CFLAGS) client.c crypto.h crypto.c -o client $(LIBSSL)

clean:
	rm -f $(TARGETS) *.o
