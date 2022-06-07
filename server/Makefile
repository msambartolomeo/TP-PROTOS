TARGET = server
OBJ_DIR = obj
INCLUDE_DIRS = include

SRCS  = $(wildcard *.c)
HEADERS = $(wildcard *.h) $(wildcard include/*.h)
INCLUDES = $(addprefix -I ,$(INCLUDE_DIRS))
OBJS = $(SRCS:%.c=$(OBJ_DIR)/%.o)

CC = gcc
CFLAGS = -g -O2 -std=c11 -Wall $(INCLUDES)
LDFLAGS = -pthread
LIBS = -lcheck -lsubunit -lrt -lm -lpthread

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS)

$(OBJ_DIR)/%.o: %.c $(HEADERS)
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ -c $<

run: all
	./$(TARGET)

test: all ./tests/buffer_test.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o ./tests/buffer_test.test ./tests/buffer_test.o $(LIBS)
	./tests/buffer_test.test

clean:
	@rm -Rf $(OBJ_DIR) $(TARGET)
	@rm -Rf ./tests/*.o ./tests/*.test

.PHONY: clean
