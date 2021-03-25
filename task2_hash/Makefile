CC = g++
CFLAGS = -Wall -pedantic
LDFLAGS = -lcrypto

all: main.out
run:
	for number in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 ; do \
		echo "Test for $$number zero bits:"; \
		./main.out $$number ; \
		echo ""; \
	done
%.out: %.cpp
	$(CC) $(CFLAGS) -o $@  $< $(LDFLAGS)
