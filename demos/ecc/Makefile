CFLAGS := -g -Wall -Wextra -I../../include ../../libcwrap.a -lcrypto

.PHONY: all clean

TARGET_FILES := ecc_keygen_serialization ecc_sign

all: $(TARGET_FILES)

ecc_keygen_serialization: ecc_keygen_serialization.c
	$(CC) -o $@ $< $(CFLAGS)

ecc_sign: ecc_sign.c
	$(CC) -o $@ $< $(CFLAGS)

clean:
	rm -rf $(TARGET_FILES) priv.key pub.key