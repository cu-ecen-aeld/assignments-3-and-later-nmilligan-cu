#include <stdio.h>
#include <syslog.h>

int main( int argc, char *argv[]){
	openlog(NULL, 0, LOG_USER);
	
	if ( argc < 3) {
		
		syslog(LOG_ERR, "Writer requires two arguments");
		return 1;
	}
	
	
	FILE *fp = fopen(argv[1], "w");
	
	if (fp == NULL){
		syslog(LOG_ERR, "Error opening/creating file");
	} 
	
	syslog(LOG_DEBUG, "Writing %s to %s", argv[2], argv[1]);
	int err = fputs(argv[2], fp);
	fclose(fp);
	
	if (err == EOF){
		syslog(LOG_ERR, "Error writing file");
		return 1;
	} 
	
	return 0;
}
