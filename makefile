CC=g++
CFLAGS=-I.
LFLAGS=-lntl -lgmp
DEPS = sha256.h sha512.h

all: p256 ed25519
p256.o: p256.cpp sha256.h
	$(CC) -c -o $@ $< $(CFLAGS)
sha256.o: sha256.c sha256.h
	$(CC) -c -o $@ $< $(CFLAGS)
ed25519.o: ed25519.cpp sha512.h
	$(CC) -c -o $@ $< $(CFLAGS)
sha512.o: sha512.c sha512.h
	$(CC) -c -o $@ $< $(CFLAGS)

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

p256: p256.o sha256.o
	$(CC) $(LFLAGS) -o p256 p256.o sha256.o
ed25519: ed25519.o sha512.o
	$(CC) $(LFLAGS) -o ed25519 ed25519.o sha512.o

