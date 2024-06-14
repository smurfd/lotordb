CL:=clang -O3
all: tests crypto client server

tests: tests/tests
	make -f tests/Makefile

crypto: crypto.o
	${CL} -c crypto.c

client: crypto.o
  ${CL} -o client client.c crypto.o -fuse-ld=lld -lpthread

server: crypto.o
  ${CL} -o server server.c crypto.o -fuse-ld=lld -lpthread

clean :
	rm tests/tests crypto.o client server
