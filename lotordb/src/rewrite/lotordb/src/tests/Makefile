CC:=gcc -O3 -Wall -pedantic -std=c99
BUILD:=../.build

all: tests

tests:
	${CC} -o ${BUILD}/tests tests.c ${BUILD}/hash.o ${BUILD}/aes.o -lm
	${BUILD}/tests
