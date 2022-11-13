CFLAGS := -g -Wall -Wextra -I../../include ../../libcwrap.a -lcrypto

.PHONY: all clean

TARGET_FILES := ecdh x448 x25519

all: $(TARGET_FILES)

ecdh: ecdh.c
	$(CC) -o $@ $< $(CFLAGS)

x448: x448.c
	$(CC) -o $@ $< $(CFLAGS)

x25519: x25519.c
	$(CC) -o $@ $< $(CFLAGS)

clean:
	rm -rf $(TARGET_FILES)