TARGET = client
OBJ_DIR = obj
INCLUDE_DIRS = include

SRCS  = $(shell find . -type f -name *.c)
HEADERS = $(shell find . -type f -name *.h) $(shell find include -type f -name *.h)
INCLUDES = $(addprefix -I ,$(INCLUDE_DIRS))
OBJS = $(SRCS:%.c=$(OBJ_DIR)/%.o)

CC = gcc
CFLAGS = -O2 -Wall $(INCLUDES)
LDFLAGS = -lm

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS)

$(OBJ_DIR)/%.o: %.c $(HEADERS)
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ -c $<

run: all
	@./$(TARGET)

clean:
	@rm -Rf $(OBJ_DIR) $(TARGET)

.PHONY: clean
