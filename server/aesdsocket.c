#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <stdbool.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <syslog.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string.h>
#include <arpa/inet.h>
#include "read_line.h"
#include <errno.h>
#include "queue.h"
#include <pthread.h>
#include "../aesd-char-driver/aesd_ioctl.h"

#define PORT "9000" //connection port
#define BUF_SIZE 20000
#define USE_AESD_CHAR_DEVICE 1

#ifdef USE_AESD_CHAR_DEVICE
char* data_path = "/dev/aesdchar";
#else
char* data_path = "/var/tmp/aesdsocketdata";
#endif

bool caught_int = false;

struct thread_node{
	pthread_mutex_t *mutex;
	pthread_t *self;
	int fd;
    /**
     * Set to true if the thread completed with success, false
     * if an error occurred.
     */
    bool thread_complete;
	TAILQ_ENTRY(thread_node) nodes;
};

typedef TAILQ_HEAD(head_s, node) head_t;

struct timer_data{
	pthread_mutex_t *mutex;
};

void remove_complete_threads(head_t *head){
	syslog(LOG_INFO, "Removing complete threads\n");
	struct thread_node * e = NULL;
	struct thread_node * next = NULL;
	TAILQ_FOREACH_SAFE(e, head, nodes, next){
		if (e->thread_complete == true){
			syslog(LOG_INFO, "Found complete thread\n");
			TAILQ_REMOVE(head, e, nodes);
			pthread_join(*e->self, NULL);
			free(e);
			e = NULL;
		}
	}
}

void free_queue(head_t *head){
	syslog(LOG_INFO, "Freeing linked list\n");
	struct thread_node * e = NULL;
	struct thread_node * next = NULL;
	TAILQ_FOREACH_SAFE(e, head, nodes, next){
		TAILQ_REMOVE(head, e, nodes);
		pthread_kill(*e->self, NULL);
		pthread_join(*e->self, NULL);
		close(e->fd);
		free(e);
		e = NULL;
	}
	syslog(LOG_INFO, "Done freeing linked list\n");
}

static void signal_handler (int signal_num){
	if (signal_num == SIGINT || signal_num == SIGTERM){
		syslog(LOG_INFO, "Caught signal, exiting\n");
		caught_int = true;
	}
}


void* timer_thread(void* thread_param)
{
	struct timer_data* thread_data_args = (struct timer_data *) thread_param;
	time_t t;
	struct timespec timer;
	struct timespec remain;
	struct tm *tmp;
	char outstr[200];
	char stamp[400];
	int data_fd;
	
	syslog(LOG_INFO, "starting timer thread\n");
	timer.tv_sec = 10;
	while(!caught_int) { 
		// sleep
		clock_nanosleep(CLOCK_MONOTONIC,0, &timer, &remain);
		t = time(NULL);
		tmp = localtime(&t);
		int rc = pthread_mutex_lock(thread_data_args->mutex);
		data_fd = open(data_path, O_CREAT|O_APPEND|O_RDWR, S_IRWXU);
		if(rc == 0){
			//format timestamp
			strftime(outstr, sizeof(outstr), "%a, %d %b %Y %T %z", tmp);
			int len = sprintf(stamp, "timestamp:%s\n", outstr);
			pwrite(data_fd, stamp, len, SEEK_END);
			close(data_fd);
			rc = pthread_mutex_unlock(thread_data_args->mutex);
		}
	}
}


void* socket_thread(void* thread_param)
{
	struct thread_node* thread_data_args = (struct thread_node *) thread_param;
	char buf[BUF_SIZE];
	char buf2[BUF_SIZE];
	int data_fd;
	char *ptr_x, *ptr_y;
	char search_str[] = "AESDCHAR_IOCSEEKTO:";
	int index;
	bool ioctl_cmd = true;

    int rc = pthread_mutex_lock(thread_data_args->mutex);
    data_fd = open(data_path, O_CREAT|O_APPEND|O_RDWR, S_IRWXU);
    if(rc == 0){
		
		ssize_t nread = readLine(thread_data_args->fd, buf, BUF_SIZE);
		
		for (index=0; index<strlen(search_str); index++){
			if (buf[index] != search_str[index]){
				ioctl_cmd = false;
				break;
			}
		}
		
		syslog(LOG_INFO, "Received an ioc\n");
		if (USE_AESD_CHAR_DEVICE && ioctl_cmd){
			syslog(LOG_INFO, "Received an ioc\n");
			ptr_x = strtok(buf, ":");
			ptr_x = strtok(NULL, ",");
			ptr_y = strtok(NULL, ",");
			syslog(LOG_INFO, "Values %s, %s\n", ptr_x, ptr_y);
			
			syslog(LOG_INFO, "Preparing seekto object.\n");
			struct aesd_seekto *seek_to = (struct aesd_seekto *) malloc(sizeof(struct aesd_seekto));
			seek_to->write_cmd = atoi(ptr_x);
			seek_to->write_cmd_offset = atoi(ptr_y);
			syslog(LOG_INFO, "Calling ioctl.\n");
			ioctl(fileno(data_fd), AESDCHAR_IOCSEEKTO, &seek_to);
		}
		else{
			pwrite(data_fd, buf, nread, SEEK_END);
			fsync(data_fd);
			lseek(data_fd, 0, SEEK_SET);
		}

		syslog(LOG_INFO, "Writing.\n");
        while ((nread = read(data_fd, buf2, BUF_SIZE)) > 0){
			write(thread_data_args->fd, buf2, nread);
		}
        close(thread_data_args->fd);
		close(data_fd);
		rc = pthread_mutex_unlock(thread_data_args->mutex);
		
	}
	thread_data_args->thread_complete = true;
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
	pthread_mutex_t mutex;
	int status, ret;
	struct addrinfo hints;
	struct addrinfo *result, *rp;
	int sfd, s;
	int opt = 1;
	struct sockaddr_storage peer_addr;
	socklen_t peer_addr_len;
	//init linked list
	TAILQ_HEAD(head_s, node) head;
	TAILQ_INIT(&head);
	
	
	
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
	hints.ai_socktype = SOCK_STREAM; /* Stream socket */
	hints.ai_flags = AI_PASSIVE;    /* For wildcard IP address */
	hints.ai_protocol = 0;          /* Any protocol */ 
	hints.ai_canonname = NULL;
	hints.ai_addr = NULL;
	hints.ai_next = NULL;

	s = getaddrinfo("0.0.0.0", PORT, &hints, &result);
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
    
    pthread_mutex_init(&mutex,NULL);
    
    #ifndef USE_AESD_CHAR_DEVICE
    pthread_t t_thread;
	struct timer_data *timer_param = (struct timer_data *) malloc(sizeof(struct timer_data));
	timer_param->mutex = &mutex;
	
	int rc = pthread_create(&t_thread, NULL, &timer_thread, (void*) timer_param);
	#endif
	
    while(!caught_int) {  // main accept() loop
        peer_addr_len = sizeof peer_addr;
        int new_fd = accept(sfd, (struct sockaddr *)&peer_addr, &peer_addr_len);
        if (new_fd == -1) {
	    syslog(LOG_ERR, "Failed to accept connection %i\n", errno);
            perror("accept");
			continue;
			//exit(-1);
        }

        inet_ntop(peer_addr.ss_family,
            get_in_addr((struct sockaddr *)&peer_addr),
            s, sizeof s);
        syslog(LOG_INFO, "Accepted connection from %i \n", s);
        
		//handle threads
		pthread_t thread;
		
		struct thread_node *thread_param = (struct thread_node *) malloc(sizeof(struct thread_node));
		syslog(LOG_INFO, "preparing thread param");
		thread_param->mutex = &mutex;
		thread_param->self = &thread;
		thread_param->thread_complete = false;
		thread_param->fd = new_fd;

		syslog(LOG_INFO, "attempting pthread_create");
		int rc = pthread_create(&thread, NULL, &socket_thread, (void*) thread_param);
		syslog(LOG_INFO, "created thread");
		if(rc != 0){
			syslog(LOG_ERR, "pthread created failed: %d\n", rc);
			continue;
		}
		// add thread to linked list
		TAILQ_INSERT_TAIL(&head, thread_param, nodes);
		thread_param = NULL;
		
		// check for complete threads
		remove_complete_threads(&head);
    }
	
	#ifndef USE_AESD_CHAR_DEVICE
	pthread_join(&t_thread, NULL);
	free(timer_param);
	#endif
	
	free_queue(&head);
	close(sfd);
	
	#ifndef USE_AESD_CHAR_DEVICE
	remove(data_path);
	#endif
	
    return 0;
}
