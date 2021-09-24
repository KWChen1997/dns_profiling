#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>

#include <fcntl.h>

#include "data_analysis.h"



int main(int argc, char **argv)
{
	// Reading packet from file
	/*
	int fd = open("dns1.bin",O_RDONLY);
	size_t len;
	uint8_t *ptr;
	len = lseek(fd,0,SEEK_END);
	lseek(fd,0,SEEK_SET);
	ptr = mmap(NULL,len,PROT_READ,MAP_SHARED,fd,0);
	if(ptr == MAP_FAILED){
		perror("mmap");
		return -1;
	}

	int i = 0;
	for(i = 0; i < len; i++){
		if(i % 16 == 0)
			printf("\n");
		if(i % 8 == 0)
			printf(" ");
		printf("%02x ",*(ptr + i));
	}
	puts("");
	*/

	uint8_t data[1024];
	int sockfd;
	struct sockaddr_in servaddr, cliaddr;

	if( (sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("socket creation failed");
		exit(-1);
	}

	memset(&servaddr, 0, sizeof(servaddr));
	memset(&cliaddr, 0, sizeof(cliaddr));

	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
	servaddr.sin_port = htons(5960);

	if( bind(sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr)) < 0){
		perror("bind failed");
		exit(-1);
	}

	int len, n;
	while(1){
		len = sizeof(cliaddr);
		n = recvfrom(sockfd, (char*)data, 1024, MSG_WAITALL, (struct sockaddr *) &cliaddr, &len);

		dump_packet(data,n);
	}
	return 0;
}
