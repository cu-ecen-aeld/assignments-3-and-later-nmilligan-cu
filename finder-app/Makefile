CROSS_COMPILE = 

all: writer

clean:
	-rm -f *.o 
	-rm -f writer
	
writer: writer.o
	$(CROSS_COMPILE)gcc -o writer writer.c
