CL:=clang -O3 -Wall -pedantic
CC:=clang -O3 -Wall -pedantic
BUILD:=.build

all: keys hash tables crypto client server test

crypto:
	mkdir -p ${BUILD}
	${CL} -c crypto.c -o ${BUILD}/crypto.o

keys:
	mkdir -p ${BUILD}
	${CL} -c keys.c -o ${BUILD}/keys.o

hash:
	mkdir -p ${BUILD}
	${CL} -c hash.c -o ${BUILD}/hash.o

tables:
	mkdir -p ${BUILD}
	${CL} -c tables.c -o ${BUILD}/tables.o

client:
	${CL} -o ${BUILD}/client client.c ${BUILD}/crypto.o ${BUILD}/keys.o ${BUILD}/tables.o ${BUILD}/hash.o -fuse-ld=lld -lpthread -lm

server:
	${CL} -o ${BUILD}/server server.c ${BUILD}/crypto.o ${BUILD}/keys.o ${BUILD}/tables.o ${BUILD}/hash.o -fuse-ld=lld -lpthread -lm

test:
	make -Ctests
	${BUILD}/tests

clean:
	rm ${BUILD}/crypto.o ${BUILD}/keys.o ${BUILD}/tables.o ${BUILD}/hash.o ${BUILD}/client ${BUILD}/server ${BUILD}/tests
