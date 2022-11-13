CFLAGS := -g -Wall -Wextra -I../../include ../../libcwrap.a -lcrypto -pthread

.PHONY: all clean

TARGET_FILES := pbkdf2 hkdf scrypt argon2

all: $(TARGET_FILES)

argon2: argon2.c
	$(CC) -o $@ $< $(CFLAGS)

pbkdf2: pbkdf2.c
	$(CC) -o $@ $< $(CFLAGS)

hkdf: hkdf.c
	$(CC) -o $@ $< $(CFLAGS)

scrypt: scrypt.c
	$(CC) -o $@ $< $(CFLAGS)

clean:
	rm -rf $(TARGET_FILES)