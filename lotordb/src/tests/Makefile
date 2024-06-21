CL:=clang -O3 -Wall -pedantic
CC:=clang -O3 -Wall -pedantic

all: tests

tests:
	${CL} -o tests tests.c ../crypto.o ../keys.o ../hash.o -fuse-ld=lld -lpthread -lm