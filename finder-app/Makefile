CC=$(CROSS_COMPILE)gcc

all: writer

clean:
	-rm -f *.o 
	-rm -f writer
	
writer: writer.o
	$(CC) $(CFLAGS) -o writer writer.c
