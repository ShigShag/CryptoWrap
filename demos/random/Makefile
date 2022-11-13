CFLAGS := -g -Wall -Wextra -I../../include ../../libcwrap.a -lcrypto

.PHONY: all clean

TARGET_FILES := random

all: $(TARGET_FILES)

random: random.c
	$(CC) -o $@ $< $(CFLAGS)

clean:
	rm -rf $(TARGET_FILES)