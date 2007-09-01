# $Id$

CC=gcc
LD=gcc

CFLAGS=-g -Wall
# CFLAGS=-02

# source files
OBJS=xrelayd.o

XYSSL_DIR=../xyssl-0.7

CFLAGS+=-I$(XYSSL_DIR)/include

## dynamic linking
LDFLAGS+=-L$(XYSSL_DIR)/library
LIBS=-lxyssl

## static linking
# OBJS+=$(XYSSL_DIR)/library/libxyssl.a

xrelayd: $(OBJS)
	$(LD) $(LDFLAGS) $(LIBS) -o $@ $(OBJS)

%.o: %.c
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f *.o
	rm -f xrelayd
