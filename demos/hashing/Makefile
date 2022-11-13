CFLAGS := -g -Wall -Wextra -I../../include ../../libcwrap.a -lcrypto

.PHONY: all clean

TARGET_FILES := hash_bytes hash_file hash_stream

all: $(TARGET_FILES)

hash_bytes: hash_bytes.c
	$(CC) -o $@ $< $(CFLAGS)

hash_file: hash_file.c
	$(CC) -o $@ $< $(CFLAGS)

hash_stream: hash_stream.c
	$(CC) -o $@ $< $(CFLAGS)

clean:
	rm -rf $(TARGET_FILES)