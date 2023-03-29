
CC = /usr/bin/clang

CFLAGS = -I. -std=c99
CFLAGS += -O3 -Wall

# Use memcpy to conver blocks[] in md5_transform.
# CFLAGS += -DMD5_LITTLE_ENDIAN

PROG = test-md5
OBJS = test-md5.o md5.o

.SUFFIXES: .c .o
.PHONY: all clean
all: $(PROG)

$(PROG): $(OBJS)
	$(CC) $(CFLAGS) -o $(PROG) $(OBJS)

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(PROG) $(OBJS)

