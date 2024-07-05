CL:=clang -O3 -Wall -pedantic
CC:=clang -O3 -Wall -pedantic
BUILD:=.build

all: mkbuilddir db_keystore hash db_tables crypto crypto_server crypto_client client server test

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

client:
	${CL} -o ${BUILD}/client client.c ${BUILD}/crypto.o ${BUILD}/crypto_client.o ${BUILD}/db_keystore.o ${BUILD}/db_tables.o ${BUILD}/hash_tooling.o ${BUILD}/hash.o -fuse-ld=lld -lpthread -lm

server:
	${CL} -o ${BUILD}/server server.c ${BUILD}/crypto.o ${BUILD}/crypto_server.o ${BUILD}/db_keystore.o ${BUILD}/db_tables.o ${BUILD}/hash_tooling.o ${BUILD}/hash.o -fuse-ld=lld -lpthread -lm

test:
	make -Ctests
	${BUILD}/tests

clean:
	rm ${BUILD}/crypto.o ${BUILD}/crypto_client.o ${BUILD}/crypto_server.o ${BUILD}/db_keystore.o ${BUILD}/db_tables.o ${BUILD}/hash.o ${BUILD}/hash_tooling.o ${BUILD}/client ${BUILD}/server ${BUILD}/tests
