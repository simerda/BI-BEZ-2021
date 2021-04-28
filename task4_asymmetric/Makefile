CC = g++
CFLAGS = -Wall -pedantic
LDFLAGS = -lcrypto

all: open.out seal.out
%.out: %.cpp
	$(CC) $(CFLAGS) -o $@  $< $(LDFLAGS)
