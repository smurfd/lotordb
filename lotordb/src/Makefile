CL := gcc -O3 -Wall -pedantic -std=c99
CC := gcc -O3 -Wall -pedantic -std=c99
BUILD:=.build

all: mkbuilddir hash ciphers ciphers_aes_gcm keys db_keystore db_tables crypto client server test
#crypto_server crypto_client
mkbuilddir:
	mkdir -p ${BUILD}

crypto:
	${CL} -c crypto.c -o ${BUILD}/crypto.o

#crypto_server:
#	${CL} -c crypto_server.c -o ${BUILD}/crypto_server.o

#crypto_client:
#	${CL} -c crypto_client.c -o ${BUILD}/crypto_client.o

db_keystore:
	${CL} -c db_keystore.c -o ${BUILD}/db_keystore.o

hash:
	${CL} -c hash_tooling.c -o ${BUILD}/hash_tooling.o
	${CL} -c hash.c -o ${BUILD}/hash.o

db_tables:
	${CL} -c db_tables.c -o ${BUILD}/db_tables.o

ciphers:
	${CL} -c ciphers.c -o ${BUILD}/ciphers.o

ciphers_aes_gcm:
	${CL} -c ciphers_aes_gcm.c -o ${BUILD}/ciphers_aes_gcm.o

keys:
	${CL} -c keys.c -o ${BUILD}/keys.o

client:
	${CL} -o ${BUILD}/client crypto_client.c ${BUILD}/crypto.o ${BUILD}/hash.o ${BUILD}/hash_tooling.o\
	  ${BUILD}/db_keystore.o ${BUILD}/db_tables.o ${BUILD}/ciphers_aes_gcm.o -lpthread -lm

server:
	${CL} -o ${BUILD}/server crypto_server.c ${BUILD}/crypto.o ${BUILD}/hash_tooling.o ${BUILD}/hash.o\
	  ${BUILD}/db_keystore.o ${BUILD}/db_tables.o ${BUILD}/ciphers_aes_gcm.o -lpthread -lm

test:
	make -Ctests
	${BUILD}/tests

clean:
	rm ${BUILD}/crypto.o ${BUILD}/db_keystore.o ${BUILD}/db_tables.o\
	  ${BUILD}/hash.o ${BUILD}/hash_tooling.o ${BUILD}/ciphers.o ${BUILD}/keys.o ${BUILD}/ciphers_aes_gcm.o\
	  ${BUILD}/client ${BUILD}/server ${BUILD}/tests
