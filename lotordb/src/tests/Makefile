CL:=clang -O3 -Wall -pedantic
CC:=clang -O3 -Wall -pedantic
BUILD:=../.build

all: tests

tests:
	${CL} -o ${BUILD}/tests tests.c ${BUILD}/crypto.o ${BUILD}/keys.o ${BUILD}/hash.o ${BUILD}/hash_tooling.o ${BUILD}/tables.o -fuse-ld=lld -lpthread -lm
