CL:=clang -O3
all: crypto client server tests

tests: crypto.o
	make -Ctests

crypto: crypto.o
	${CL} -c crypto.c

client: crypto.o
	${CL} -o client client.c crypto.o -fuse-ld=lld -lpthread -lm

server: crypto.o
	${CL} -o server server.c crypto.o -fuse-ld=lld -lpthread -lm

clean:
	rm tests/tests crypto.o client server
