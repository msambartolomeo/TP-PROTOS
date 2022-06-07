SERVER=build/server
CLIENT=build/client

all: server client

server:
	@cd server; $(MAKE)
	@mkdir -p build
	@cp server/server $(SERVER)

client:
	@cd client; $(MAKE)
	@mkdir -p build
	@cp client/client $(CLIENT)

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
