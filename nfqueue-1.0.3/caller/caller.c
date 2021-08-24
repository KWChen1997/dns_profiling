#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>

int main(){
	pid_t pid;
	int pipefd[2];
	if(pipe2(pipefd, O_DIRECT) == -1){
		perror("pipe");
		exit(-1);
	}

	if((pid = fork()) == -1){
		perror("fork");
		exit(-1);
	}
	if(pid == 0){
		// child
		// write to pipefd[1]
		dup2(pipefd[1],STDOUT_FILENO);
		close(pipefd[0]);
		if(execl("../dnsparser", "dnsparser",NULL) == -1){
			perror("exec");
			exit(-1);
		}
	}
	else{
		// parent
		// read from pipefd[0]
		close(pipefd[1]);
		int rc;
		char buf[1024];
		int status;
		while(1){
			rc = read(pipefd[0], buf, sizeof(buf));
			if(rc == 0)
				break;
			printf("%s",buf);
		}
		waitpid(pid,NULL,0);
	}
	
	return 0;
}
