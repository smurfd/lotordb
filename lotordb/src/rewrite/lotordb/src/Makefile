CC := gcc -O3 -Wall -pedantic -std=c99
BUILD := .build

all: mkbuilddir hash aes test

mkbuilddir:
	mkdir -p ${BUILD}

hash:
	${CC} -c hash.c -o .build/hash.o

aes:
	${CC} -c aes.c -o .build/aes.o

test:
	make -Ctests
