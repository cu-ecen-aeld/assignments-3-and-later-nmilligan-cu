CC ?= $(CROSS_COMPILE)gcc
CFLAGS ?= -g -Wall
LDFLAGS ?= -pthread -lrt


all: aesdsocket

clean:
	-rm -f *.o 
	-rm -f aesdsocket
	
aesdsocket: aesdsocket.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o aesdsocket aesdsocket.c read_line.c
