CC=gcc

all: sniffer

sniffer: sniffer.o
	$(CC) $< -o $@

sniffer.o: sniffer.c
	$(CC) -c $< -o $@
