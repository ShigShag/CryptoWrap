CFLAGS := -g -Wall -Wextra -I../../include ../../libcwrap.a -lcrypto

.PHONY: all clean

TARGET_FILES := base64_raw base64_file base64_stream

all: $(TARGET_FILES)

base64_raw: base64_raw.c
	$(CC) -o $@ $< $(CFLAGS)

base64_file: base64_file.c
	$(CC) -o $@ $< $(CFLAGS)	
	
base64_stream: base64_stream.c
	$(CC) -o $@ $< $(CFLAGS)	

clean:
	rm -rf $(TARGET_FILES) base64_file_interface.txt base64_file_interface_out.txt