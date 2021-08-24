#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(){
	int i = 0;
	
	for( i = 0 ; i < 10 ; i ++ ){
		write(STDOUT_FILENO,"Sleeping ...\n", sizeof("Sleeping ...\n"));
		sleep(1);
	}
	write(STDOUT_FILENO, "Bye!\n", sizeof("Bye!\n"));
	return 0;
}
