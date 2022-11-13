CFLAGS := -g -Wall -Wextra -I../../include ../../libcwrap.a -lcrypto

.PHONY: all clean

TARGET_FILES := rsa_key_gen_serialization rsa_signature rsa_encrypt

all: $(TARGET_FILES)

rsa_key_gen_serialization: rsa_key_gen_serialization.c
	$(CC) -o $@ $< $(CFLAGS)

rsa_signature: rsa_signature.c
	$(CC) -o $@ $< $(CFLAGS)

rsa_encrypt: rsa_encrypt.c
	$(CC) -o $@ $< $(CFLAGS)

clean:
	rm -rf $(TARGET_FILES) priv.key pub.key