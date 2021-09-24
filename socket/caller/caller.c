#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>

#include <mysql.h>

struct qry {
	char dst[16];
	char name[256];
	char addr[16];
};

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
		if(execl("../dnsparser", "dnsparser", "2>/dev/null",NULL) == -1){
			perror("exec");
			exit(-1);
		}
	}
	else{
		// parent
		// read from pipefd[0]
		close(pipefd[1]);
		/*
		MYSQL *con = mysql_init(NULL);
		if(con == NULL){
			fprintf(stderr, "%s\n", mysql_error(con));
			kill(pid, SIGKILL);
			exit(-1);
		}
	
		if(mysql_real_connect(con, "localhost", "root", "kwchen", "dnsprofile", 0, NULL, 0) == NULL){
			fprintf(stderr, "%s\n", mysql_error(con));
			kill(pid, SIGKILL);
			mysql_close(con);
			exit(-1);
		}*/
		/*
		if(mysql_query(con, "USE dnsprofile;")){
			fprintf(stderr, "%s\n", mysql_error(con));
			kill(pid, SIGKILL);
			mysql_close(con);
			exit(-1);
		}
		*/
		struct qry qry;
		int rc;
		char buf[1024];
		int status;
		while(1){
			rc = read(pipefd[0], &qry, sizeof(struct qry));
			if(rc == 0)
				break;
			if(strcmp(qry.name,"") == 0 && strcmp(qry.addr,"") == 0){
				printf("-------------------------------------------\n");
				continue;
			}
			snprintf(buf,1024,"dst %s qry_name %s ip %s\n",qry.dst, qry.name, qry.addr);
			printf("%s", buf);
		}
		waitpid(pid,NULL,0);
	}
	
	return 0;
}
