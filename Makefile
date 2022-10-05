
#
# Makefile for hw1
#

CC  = gcc
CXX = g++

INCLUDES = -I./Libraries/crypto-algorithms
CFLAGS   = -g -Wall $(INCLUDES)
CXXFLAGS = -g -Wall $(INCLUDES)

LDFLAGS = -g 
LDLIBS = -lm

.PHONY: default
default: cstore

.PHONY: clean
clean:
	rm -rf *.o *~ cstore *.dSYM 

cstore: cstore.o sha256.o aes.o
	$(CC) $(LDFLAGS) cstore.o sha256.o aes.o $(LDLIBS) -o cstore 

cstore.o: cstore.c cstore.h
	$(CC) $(CFLAGS) -c cstore.c

sha256.o: ./Libraries/crypto-algorithms/sha256.c ./Libraries/crypto-algorithms/sha256.h
	$(CC) -c $(CFLAGS) ./Libraries/crypto-algorithms/sha256.c 

aes.o: ./Libraries/crypto-algorithms/aes.c ./Libraries/crypto-algorithms/aes.h
	$(CC) -c $(CFLAGS) ./Libraries/crypto-algorithms/aes.c 

