ARGON2_DIR = argon2

# Get all c source files
SRC_FILES := $(wildcard *.c)

# Convert c files to objective files in parent directory
OBJ_FILES := $(addprefix $(OBJ_DIR_RELATIVE), $(SRC_FILES:.c=.o))

.PHONY: all argon2

all: $(OBJ_FILES) argon2

$(OBJ_DIR_RELATIVE)%.o: %.c 
	$(CC) -o $@ -c $^ $(CFLAGS)

argon2:
	$(MAKE) -C $(ARGON2_DIR)