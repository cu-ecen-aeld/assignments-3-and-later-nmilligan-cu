#include "systemcalls.h"
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
/**
 * @param cmd the command to execute with system()
 * @return true if the command in @param cmd was executed
 *   successfully using the system() call, false if an error occurred,
 *   either in invocation of the system() call, or if a non-zero return
 *   value was returned by the command issued in @param cmd.
*/
bool do_system(const char *cmd)
{
	int val = system(cmd);
	if (val < 0){
		return -1;
	}

    return true;
}

/**
* @param count -The numbers of variables passed to the function. The variables are command to execute.
*   followed by arguments to pass to the command
*   Since exec() does not perform path expansion, the command to execute needs
*   to be an absolute path.
* @param ... - A list of 1 or more arguments after the @param count argument.
*   The first is always the full path to the command to execute with execv()
*   The remaining arguments are a list of arguments to pass to the command in execv()
* @return true if the command @param ... with arguments @param arguments were executed successfully
*   using the execv() call, false if an error occurred, either in invocation of the
*   fork, waitpid, or execv() command, or if a non-zero return value was returned
*   by the command issued in @param arguments with the specified arguments.
*/

bool do_exec(int count, ...)
{
    va_list args;
    va_start(args, count);
    char * command[count+1];
    int status = 0;
    int i;
    int err = 0;
   
    for(i=0; i<count; i++)
    {
        command[i] = va_arg(args, char *);
    }
    command[count] = NULL;
    
	pid_t pid = fork();
	
	if (pid == 0){
		err = execv(command[0], command);
		if (err < 0){
			printf("returning false");
			return -1;
		}
	}
	
	
	err = waitpid(pid, &status, 0);
	if (err < 0){
			return -1;
	}
	
    va_end(args);

    return (WEXITSTATUS(status) == 0);
}

/**
* @param outputfile - The full path to the file to write with command output.
*   This file will be closed at completion of the function call.
* All other parameters, see do_exec above
*/
bool do_exec_redirect(const char *outputfile, int count, ...)
{
    va_list args;
    va_start(args, count);
    char * command[count+1];
    int i;
    int err = 0;
    int status;
    for(i=0; i<count; i++)
    {
        command[i] = va_arg(args, char *);

    }

    command[count] = NULL;
    

    pid_t pid = fork();
	if (pid == 0){
		int fd = open(outputfile, O_WRONLY);
		dup2(fd, 1);
		err = execv(command[0], command);
		if (err < 0){
			return -1;
		}
	}
	
	int err_1 = waitpid(pid, &status, 0);
	if (err_1 < 0){
		return -1;
	}
	
    va_end(args);

    return (WEXITSTATUS(status) == 0);
}
