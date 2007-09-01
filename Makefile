# $Id$
# 
# if you want to compile against a compiled but not installed xyssl sourcetree
# XYSSL_SOURCE=/path/to/xyssl-src

DSTROOT=/usr/local
BINDIR=$(DSTROOT)/bin

CC=gcc
LD=gcc

CFLAGS=-g -Wall
LIBS=-lxyssl

ifneq ($(XYSSL_SOURCE),)
	CPPFLAGS+=-I$(XYSSL_SOURCE)/include
	LDFLAGS+=-L$(XYSSL_SOURCE)/library
endif

# source files
OBJS=xrelayd.o

xrelayd: $(OBJS)
	$(LD) $(OBJS) $(LDFLAGS) $(LIBS) -o $@

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $<

install: xrelayd
	mkdir -p $(DSTROOT)
	install -m0755 xrelayd $(BINDIR)

.PHONY: uninstall
uninstall:
	rm -f $(BINDIR)/xrelayd

.PHONY: clean
clean:
	rm -f *.o
	rm -f xrelayd
