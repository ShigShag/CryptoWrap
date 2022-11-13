CFLAGS := -g -Wall -Wextra -I../../include ../../libcwrap.a -lcrypto

.PHONY: all clean

TARGET_FILES := crypt_bytes_raw crypt_file crypt_stream high_interface

all: $(TARGET_FILES)

crypt_bytes_raw: crypt_bytes_raw.c
	$(CC) -o $@ $< $(CFLAGS)

crypt_file: crypt_file.c
	$(CC) -o $@ $< $(CFLAGS)

crypt_stream: crypt_stream.c
	$(CC) -o $@ $< $(CFLAGS)

high_interface: high_interface.c
	$(CC) -o $@ $< $(CFLAGS)

clean:
	rm -rf $(TARGET_FILES) test_file test_file_two