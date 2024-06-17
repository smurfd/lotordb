CL:=clang -O3

all: tests

tests:
	${CL} -o tests tests.c ../crypto.o -fuse-ld=lld -lpthread -lm