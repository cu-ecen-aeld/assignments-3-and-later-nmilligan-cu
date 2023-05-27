CC=$(CROSS_COMPILE)gcc

all: aesdsocket

clean:
	-rm -f *.o 
	-rm -f aesdsocket
	
aesdsocket: aesdsocket.o
	$(CC) $(CFLAGS) -pthread -o aesdsocket aesdsocket.c read_line.c
