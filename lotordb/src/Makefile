CL:=clang -O3
all: tests crypto client server

tests: tests/tests
	make -f tests/Makefile

crypto: crypto.o# defs.h crypto.h
	${CL} -c crypto.c

client: crypto.o# defs.h crypto.h 
  ${CL} -o client client.c crypto.o -fuse-ld=lld -lpthread

server: crypto.o# defs.h crypto.h
  ${CL} -o server server.c crypto.o -fuse-ld=lld -lpthread

clean :
	rm tests/tests crypto.o client server
