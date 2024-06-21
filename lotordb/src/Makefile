CL:=clang -O3 -Wall -pedantic
CC:=clang -O3 -Wall -pedantic
all: crypto keys hash client server tests

tests: crypto.o keys.o
	make -Ctests
	./tests/tests

crypto: crypto.o keys.o
	${CL} -c crypto.c

keys: keys.o
	${CL} -c keys.c

hash: hash.o crypto.o
	${CL} -c hash.c

client: crypto.o keys.o hash.o
	${CL} -o client client.c crypto.o keys.o hash.o -fuse-ld=lld -lpthread -lm

server: crypto.o keys.o hash.o
	${CL} -o server server.c crypto.o keys.o hash.o -fuse-ld=lld -lpthread -lm

clean:
	rm tests/tests crypto.o keys.o hash.o client server
