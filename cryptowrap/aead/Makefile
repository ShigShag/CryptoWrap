# Get all c source files
SRC_FILES := $(wildcard *.c)

# Convert c files to objective files in parent directory
OBJ_FILES := $(addprefix $(OBJ_DIR_RELATIVE), $(SRC_FILES:.c=.o))

.PHONY: all

all: $(OBJ_FILES) 

$(OBJ_DIR_RELATIVE)%.o: %.c 
	$(CC) -o $@ -c $^ $(CFLAGS)