# Local directory which holds the objective files
OBJ_DIR_LOCAL := obj
OBJ_FILES := $(OBJ_DIR_LOCAL)/*.o

PUBLIC_HEADER_FILES := include/cryptowrap

# Exports to child Makefiles
CC := gcc

OBJ_DIR_RELATIVE := ../../$(OBJ_DIR_LOCAL)/
CFLAGS := -g -Wall -Wextra -pthread -I../../include/

# Every source directory
SOURCE_DIR := cryptowrap
SOURCE_DIRECTORIES := $(foreach dir, $(wildcard $(SOURCE_DIR)/*/), $(dir))

STATIC := libcwrap.a
SHARED := libcwrap.so
LDLIBS := $(STATIC) -pthread

# Default installation paths
HEADER_INSTALLATION_PATH := /usr/include
LIBRARY_INSTALLATION_PATH := /usr/lib

.PHONY: static shared test clean $(SOURCE_DIRECTORIES)

all: $(STATIC)

install: $(SHARED) copy_header copy_lib
copy_header: $(COPY_HEADER)
static: $(STATIC)
shared: $(SHARED) 


$(STATIC): clean $(OBJ_DIR_LOCAL) $(SOURCE_DIRECTORIES)
	ar -crs $@ $(OBJ_FILES)

# Add fPIC flag for shared library
$(SHARED): CFLAGS += -fPIC
$(SHARED): clean $(OBJ_DIR_LOCAL) $(SOURCE_DIRECTORIES)
	$(CC) -o $@ -shared -fPIC $(OBJ_FILES)

export CFLAGS OBJ_DIR_RELATIVE CC

copy_header:
	cp -r $(PUBLIC_HEADER_FILES) $(HEADER_INSTALLATION_PATH)

copy_lib:
	cp $(SHARED) $(LIBRARY_INSTALLATION_PATH)

$(SOURCE_DIRECTORIES):
	$(MAKE) -C $@

$(OBJ_DIR_LOCAL):
	mkdir -p $@

# Testing
TEST_CFLAGS := -Wall -g -pthread

TEST_DIR := test
TEST_DIR_BIN := $(TEST_DIR)/bin
TEST_SRC_FILES := $(wildcard $(TEST_DIR)/*.c)
TEST_BIN_FILES := $(patsubst $(TEST_DIR)/%.c, $(TEST_DIR_BIN)/%, $(TEST_SRC_FILES))

.PHONY += $(TEST_DIR_BIN) $(TEST_DIR_BIN)/%

test: static_test
static_test: TEST_CFLAGS += -I./include/ $(STATIC) 
static_test: $(TEST_DIR_BIN) $(TEST_BIN_FILES)
	for test in $(TEST_BIN_FILES) ; do \
		./$$test ; \
	done

shared_test: TEST_CFLAGS += -lcwrap -I./include/
shared_test: $(TEST_DIR_BIN) $(TEST_BIN_FILES)
	for test in $(TEST_BIN_FILES) ; do \
		./$$test ; \
	done

$(TEST_DIR_BIN)/%: $(TEST_DIR)/%.c
	$(CC) $< -o $@ $(TEST_CFLAGS) -lcriterion -lcrypto

$(TEST_DIR_BIN):
	mkdir -p $@

clean:
	rm -rf $(OBJ_DIR_LOCAL)
	rm -rf $(STATIC)
	rm -rf $(TEST_DIR_BIN)
	rm -rf $(SHARED)
