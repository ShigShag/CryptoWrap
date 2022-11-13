CFLAGS := -g -Wall -Wextra -I../../include ../../libcwrap.a -lcrypto

.PHONY: all clean

TARGET_FILES := crypt_bytes_raw crypt_stream

all: $(TARGET_FILES)

crypt_bytes_raw: crypt_bytes_raw.c
	$(CC) -o $@ $< $(CFLAGS)

crypt_stream: crypt_stream.c
	$(CC) -o $@ $< $(CFLAGS)	

clean:
	rm -rf $(TARGET_FILES) priv.key pub.key