CL := gcc -O3 -Wall -pedantic -std=c99
CC := gcc -O3 -Wall -pedantic -std=c99
BUILD:=.build

all: mkbuilddir hash ciphers keys db_keystore db_tables crypto crypto_server crypto_client test

mkbuilddir:
	mkdir -p ${BUILD}

crypto:
	${CL} -c crypto.c -o ${BUILD}/crypto.o

crypto_server:
	${CL} -c crypto_server.c -o ${BUILD}/crypto_server.o

crypto_client:
	${CL} -c crypto_client.c -o ${BUILD}/crypto_client.o

db_keystore:
	${CL} -c db_keystore.c -o ${BUILD}/db_keystore.o

hash:
	${CL} -c hash_tooling.c -o ${BUILD}/hash_tooling.o
	${CL} -c hash.c -o ${BUILD}/hash.o

db_tables:
	${CL} -c db_tables.c -o ${BUILD}/db_tables.o

ciphers:
	${CL} -c ciphers.c -o ${BUILD}/ciphers.o

keys:
	${CL} -c keys.c -o ${BUILD}/keys.o

test:
	make -Ctests
	${BUILD}/tests

clean:
	rm ${BUILD}/crypto.o ${BUILD}/db_keystore.o ${BUILD}/db_tables.o\
	  ${BUILD}/hash.o ${BUILD}/hash_tooling.o ${BUILD}/keys.o ${BUILD}/ciphers.o\
	  ${BUILD}/crypto_client.o ${BUILD}/crypto_server.o ${BUILD}/tests
