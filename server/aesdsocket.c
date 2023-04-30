#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <syslog.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string.h>
#include <arpa/inet.h>
#include "read_line.h"

#define PORT "9000" //connection port
#define BUF_SIZE 20000

bool caught_int = false;

static void signal_handler (int signal_num){
	if (signal_num == SIGINT || signal_num == SIGTERM){
		syslog(LOG_INFO, "Caught signal, exiting\n");
		caught_int = true;
	}
}

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

int main( int argc, char *argv[]){
	openlog(NULL, 0, LOG_USER);
	
	int status, ret;
	struct addrinfo hints;
	struct addrinfo *result, *rp;
	int sfd, new_fd, s, data_fd; 
	int opt = 1;
	struct sockaddr_storage peer_addr;
	socklen_t peer_addr_len;
	ssize_t nread;
	char buf[BUF_SIZE];
	char buf2[BUF_SIZE];
	
	
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
	hints.ai_socktype = SOCK_STREAM; /* Stream socket */
	hints.ai_flags = AI_PASSIVE;    /* For wildcard IP address */
	hints.ai_protocol = 0;          /* Any protocol */ 
	hints.ai_canonname = NULL;
	hints.ai_addr = NULL;
	hints.ai_next = NULL;

	s = getaddrinfo("localhost", PORT, &hints, &result);
	if (s != 0) {
		syslog(LOG_INFO, "Usage: %s host port msg...\n", PORT);
		exit(-1);
	}
	
	/* getaddrinfo() returns a list of address structures.
	Try each address until we successfully bind(2).
	If socket(2) (or bind(2)) fails, we (close the socket
	and) try the next address. */

	for (rp = result; rp != NULL; rp = rp->ai_next) {
		sfd = socket(rp->ai_family, rp->ai_socktype,
		   rp->ai_protocol);
		if (sfd == -1)
		   continue;
		
		setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
		if (bind(sfd, rp->ai_addr, rp->ai_addrlen) == 0)
		   break;                  /* Success */

		close(sfd);
	}

	freeaddrinfo(result);           /* No longer needed */
	
	if ( argv[1] != NULL && strcmp(argv[1], "-d") == 0){
		
		syslog(LOG_INFO, "Running in daemon mode.\n");
		
		pid_t process_id = fork();
		
		if (process_id < 0){
			printf("Error calling fork");
			exit(-1);
		}
		
		if (process_id > 0){
			printf("Exiting parent");
			exit(0);
		}
		
		umask(0);
		setsid();
		chdir("/");
		close(STDIN_FILENO);
		close(STDOUT_FILENO);
		close(STDERR_FILENO);
	}

	if (rp == NULL) {               /* No address succeeded */
		syslog(LOG_ERR, "Failed to bind\n");
		exit(-1);
	}
	 if (listen(sfd, 10) == -1) {
        perror("listen");
        exit(-1);
    }
    
    struct sigaction new_action;
    memset(&new_action, 0, sizeof(struct sigaction));
    new_action.sa_handler=signal_handler;
    if( sigaction(SIGTERM, &new_action, NULL) != 0){
		printf("Error registering SIGTERM");
		exit(-1);
	}
	if( sigaction(SIGINT, &new_action, NULL) != 0){
		printf("Error registering SIGTERM");
		exit(-1);
	}

    syslog(LOG_INFO, "server: waiting for connections...\n");
    
    data_fd = open("/var/tmp/aesdsocketdata", O_CREAT|O_APPEND|O_RDWR, S_IRWXU);

    while(!caught_int) {  // main accept() loop
        peer_addr_len = sizeof peer_addr;
        new_fd = accept(sfd, (struct sockaddr *)&peer_addr, &peer_addr_len);
        if (new_fd == -1) {
            perror("accept");
            continue;
        }

        inet_ntop(peer_addr.ss_family,
            get_in_addr((struct sockaddr *)&peer_addr),
            s, sizeof s);
        syslog(LOG_INFO, "Accepted connection from %i \n", s);
        
        nread = readLine(new_fd, buf, BUF_SIZE);
        pwrite(data_fd, buf, nread, SEEK_END);
        fsync(data_fd);
        lseek(data_fd, 0, SEEK_SET);
        while ((nread = read(data_fd, buf2, BUF_SIZE)) > 0){
			write(new_fd, buf2, nread);
		}
        close(new_fd);

    }
    close(new_fd);
	close(data_fd);
	close(sfd);
	remove("/var/tmp/aesdsocketdata");
    return 0;
}
