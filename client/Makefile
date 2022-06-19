TARGET = client
OBJ_DIR = obj
INCLUDE_DIRS = include

SRCS  = $(wildcard *.c)
HEADERS = $(wildcard *.h) $(wildcard include/*.h)
INCLUDES = $(addprefix -I ,$(INCLUDE_DIRS))
OBJS = $(SRCS:%.c=$(OBJ_DIR)/%.o)

CFLAGS = -g -fsanitize=address -std=c11 -Wall -pedantic -pedantic-errors -Wextra -Werror -Wno-unused-parameter -Wno-implicit-fallthrough -D_POSIX_C_SOURCE=200112L $(INCLUDES)
LDFLAGS = -lm -pthread
LIBS = -lcheck -lsubunit -lrt -lm -lpthread

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(TARGET) $(OBJS)

$(OBJ_DIR)/%.o: %.c $(HEADERS)
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -o $@ -c $<

run: all
	./$(TARGET)

clean:
	@rm -Rf $(OBJ_DIR) $(TARGET)

.PHONY: clean
