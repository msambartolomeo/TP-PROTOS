TARGET = client
OBJ_DIR = obj
INCLUDE_DIRS = include

SRCS  = $(shell find . -type f -name '*.c')
HEADERS = $(shell find . -type f -name '*.h') $(shell find include -type f -name '*.h')
INCLUDES = $(addprefix -I ,$(INCLUDE_DIRS))
OBJS = $(SRCS:%.c=$(OBJ_DIR)/%.o)

CFLAGS = -g -fsanitize=address -std=c11 -Wall -pedantic -pedantic-errors -Wextra -Werror -Wno-unused-parameter -Wno-implicit-fallthrough -D_POSIX_C_SOURCE=200112L $(INCLUDES)
LDFLAGS = -lm -pthread

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(TARGET) $(OBJS)

$(OBJ_DIR)/%.o: %.c $(HEADERS)
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ -c $<

run: all
	@./$(TARGET)

clean:
	@rm -Rf $(OBJ_DIR) $(TARGET)

.PHONY: clean
