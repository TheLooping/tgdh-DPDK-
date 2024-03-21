CC = /usr/bin/gcc
CFLAGS = -g -Wall
LDFLAGS = -lssl -lcrypto -lm -lc -lpthread

SRCS := $(wildcard *.c)
BUILD_DIR := build
EXECUTABLE = $(BUILD_DIR)/tgdh_server

all: $(EXECUTABLE)

$(EXECUTABLE): $(SRCS)
	mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

clean:
	rm -rf $(BUILD_DIR)
