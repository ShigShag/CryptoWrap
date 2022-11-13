BLAKE2_DIR = blake2

# This will cause -I parameter to exist two times but that does not matter
CFLAGS += -std=c89 -O3 -Wall -I./

# Get all c source files
SRC_FILES := $(wildcard *.c)

# Add additionl parent directory
OBJ_DIR_RELATIVE := $(addprefix ../, $(OBJ_DIR_RELATIVE))

# Convert c files to objective files in parent directory
OBJ_FILES := $(addprefix $(OBJ_DIR_RELATIVE), $(SRC_FILES:.c=.o))

.PHONY: all blake2

all: $(OBJ_FILES) blake2

$(OBJ_DIR_RELATIVE)%.o: %.c 
	$(CC) -o $@ -c $^ $(CFLAGS)

blake2:
	$(MAKE) -C $(BLAKE2_DIR)