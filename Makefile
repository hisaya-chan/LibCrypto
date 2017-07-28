#
##

CC	=	gcc
CFLAGS	=  	-Wall
CFLAGS  += 	-DDEBUG -D_GNU_SOURCE
CFLAGS  += 	-g

PREFIX ?= 	${DESTDIR}/usr
LIBDIR	=	${PREFIX}/lib
INCDIR	=	${PREFIX}/include
LIBS    =       -lm

CIBLES	=	test

all: $(CIBLES)

clean:
	$(RM) -f core *.o $(CIBLES) *~


test: test.o crypt.o des.o bit.o
	$(CC) $(CFLAGS) -o $@ test.o des.o crypt.o bit.o  $(LIBS)

test.o: test.c
		$(CC) $(CFLAGS) -c test.c crypt.h

crypt.o: crypt.c
		$(CC) $(CFLAGS) -c crypt.c
des.o: des.c
		$(CC) $(CFLAGS) -c des.c

bit.o: bit.c
		$(CC) $(CFLAGS) -c bit.c

run: clean test
		./test test.txt
