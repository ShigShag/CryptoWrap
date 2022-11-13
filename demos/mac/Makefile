CFLAGS := -g -Wall -Wextra -I../../include ../../libcwrap.a -lcrypto

.PHONY: all clean

TARGET_FILES := mac_raw mac_stream
 
all: $(TARGET_FILES)

mac_raw: mac_raw.c
	$(CC) -o $@ $< $(CFLAGS)

mac_stream: mac_stream.c
	$(CC) -o $@ $< $(CFLAGS)	

clean:
	rm -rf $(TARGET_FILES)