CC=g++
CFLAGS=-I.
LFLAGS=-lntl -lgmp
DEPS = sha512.h

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

ed25519: ed25519.o sha512.o
	$(CC) $(LFLAGS) -o ed25519 ed25519.o sha512.o

