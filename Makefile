SERVER=build/socks5d
CLIENT=build/shoesc

all: server client

server:
	@cd server; $(MAKE)
	@mkdir -p build
	@cp server/socks5d $(SERVER)

client:
	@cd client; $(MAKE)
	@mkdir -p build
	@cp client/shoesc $(CLIENT)

runserver: $(SERVER)
	@./$(SERVER)

runclient: $(CLIENT)
	@./$(CLIENT)

format:
	@find . -regex '.*\.\(c\|h\)' -exec clang-format -style=file -i {} \;

clean:
	@rm -Rf build
	@cd server; $(MAKE) clean
	@cd client; $(MAKE) clean

tests:
	@cd server; $(MAKE) test
	
.PHONY: format clean server client
