
CC = /usr/bin/clang

CFLAGS = -I. -std=c99
CFLAGS += -O3 -Wall

# Use memcpy to conver blocks[] in md5_transform.
# CFLAGS += -DMD5_LITTLE_ENDIAN
# CFLAGS += -DMD4_LITTLE_ENDIAN

# Cross compile for 32-bit with clang
# CFLAGS += --target=i386-elf

OBJS = test-md4.o test-md5.o md5.o md4.o

.SUFFIXES: .c .o
.PHONY: all clean
all: test-md4 test-md5

test-md4: test-md4.o md4.o md4.h
	$(CC) $(CFLAGS) -o test-md4 test-md4.o md4.o

test-md5: test-md5.o md5.o md5.h
	$(CC) $(CFLAGS) -o test-md5 test-md5.o md5.o

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) test-md4 test-md5

