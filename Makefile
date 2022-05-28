SERVER=build/server
CLIENT=build/client

all: $(SERVER) $(CLIENT)

server: $(SERVER)
client: $(CLIENT)

$(SERVER):
	@cd server; $(MAKE)
	@mkdir -p build
	@cp server/server build/server

$(CLIENT):
	@cd client; $(MAKE)
	@mkdir -p build
	@cp client/client build/client

runserver: $(SERVER)
	@./build/server

runclient: $(CLIENT)
	@./build/client

clean:
	@rm -Rf build
	@cd server; $(MAKE) clean
	@cd client; $(MAKE) clean
	
.PHONY: clean
