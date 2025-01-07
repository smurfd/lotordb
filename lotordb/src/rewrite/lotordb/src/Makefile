CC := gcc -O3 -Wall -pedantic -std=c99
BUILD := .build

all: mkbuilddir hash ecc crypto crypto_server crypto_client db_keystore db_tables test
local: mkbuilddir hash ecc crypto crypto_server crypto_client db_keystore db_tables test_local

mkbuilddir:
	mkdir -p ${BUILD}

hash:
	${CC} -c hash.c -o .build/hash.o

ecc:
	${CC} -c ecc.c -o .build/ecc.o

crypto:
	${CC} -c crypto.c -o ${BUILD}/crypto.o

crypto_server:
	${CC} -c examples/tables_example_server.c -o ${BUILD}/tables_server.o
	${CC} -c examples/keys_example_server.c -o ${BUILD}/keys_server.o
	${CC} -c crypto_server.c -o ${BUILD}/crypto_server.o

crypto_client:
	${CC} -c examples/tables_example_client.c -o ${BUILD}/tables_client.o
	${CC} -c examples/keys_example_client.c -o ${BUILD}/keys_client.o
	${CC} -c crypto_client.c -o ${BUILD}/crypto_client.o

db_keystore:
	${CC} -c db_keystore.c -o ${BUILD}/db_keystore.o

db_tables:
	${CC} -c db_tables.c -o ${BUILD}/db_tables.o

test:
	make -Ctests

test_local:
	make -Ctests local
