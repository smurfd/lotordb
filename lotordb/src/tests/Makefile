CL:=clang -O3

tests:
	${CL} -o tests tests.o -fuse-ld=lld

tests.o: tests.c ../defs.h
	${CL} -c tests.c

