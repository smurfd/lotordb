CC := gcc -O3 -Wall -pedantic -std=c99
BUILD:=.build

all: mkbuilddir hash aes test
#ciphers keys db_keystore db_tables crypto crypto_server crypto_client test

mkbuilddir:
	mkdir -p ${BUILD}

hash:
	${CC} -c hash.c -o .build/hash.o

aes:
	${CC} -c aes.c -o .build/aes.o

test:
	make -Ctests
