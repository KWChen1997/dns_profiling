#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <string.h>
#include <time.h>
#include <linux/ip.h>
#include <netinet/ip6.h>
#include <linux/udp.h>

#ifndef __linux
#include <net/if.h>
#include <netinet/in.h>
#include <net/if_dl.h>
#include <net/ethernet.h>
#endif

#include "data_analysis.h"
/*
void analyze(char *data_file){
	u_char data_buf[MTU] = {0};
	memset(data_buf, '\0', sizeof(data_buf));
	int i = 0;
	FILE *fptr = fopen(data_file, "rb");
	if(!fptr){
		perror("fopen");
		exit(1);
	}

	for(i=0; !feof(fptr); i++)
		fscanf(fptr, "%c", &data_buf[i]);
	fclose(fptr);

	u_int32_t caplen = i-1;
	pcap_analyze(caplen, data_buf);

	// analysis result
	hashmap_show(&hm);
	wrt_csv(&hm);
	hashmap_free(&hm);
}
*/
/*
int main(int argc, char const *argv[]) {
	char pcap_file[50];
	int cmd_opt = 0;
	hashmap_init(&hm);

	while(1) {
		cmd_opt = getopt(argc, (char **)argv, "hf:");
		if (cmd_opt == -1) break;

		switch (cmd_opt) {
			case 'h':
				usage();
				return 0;
			case 'f':
				sprintf(pcap_file, "%s", optarg);
				break;
			default:
				fprintf(stderr, "Not supported option\n");
				usage();
				break;
		}
	}
	analyze(pcap_file);
	return 0;
}
*/
/*
void pcap_analyze(const u_int32_t caplen, const u_char *content) {
	struct ether_header *ethernet = (struct ether_header *)content;
	u_int16_t type = ntohs(ethernet->ether_type);

	if(type == ETHERTYPE_IP) {
		struct ip *ip = (struct ip *)(content + ETHER_HDR_LEN);
		struct udphdr *udp = (struct udphdr *)(content + ETHER_HDR_LEN + (ip->ip_hl << 2));
		
		char src_ip[INET_ADDRSTRLEN] = {0};
		char dst_ip[INET_ADDRSTRLEN] = {0};
		inet_ntop(AF_INET, &(ip->ip_src), src_ip, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, &(ip->ip_dst), dst_ip, INET_ADDRSTRLEN);

		u_int16_t source_port = ntohs(udp->uh_sport);
		u_int16_t destination_port = ntohs(udp->uh_dport);
		//printf("%s(%u) -> %s(%u)\n", src_ip, source_port, dst_ip, destination_port);

		u_char *message = (u_char *)(content + ETHER_HDR_LEN + (ip->ip_hl << 2) + 8);
		u_int32_t length = caplen - ETHER_HDR_LEN - (ip->ip_hl << 2) - 8;
		if (source_port == 53)
			dump_dns(length, message);
	}
	else if(type == ETHERTYPE_IPV6) {
		struct ip6_hdr *ip6 = (struct ip6_hdr *)(content + ETHER_HDR_LEN);
		struct udphdr *udp = (struct udphdr *)(content + ETHER_HDR_LEN + 40);

		char src_ip[INET6_ADDRSTRLEN] = {0};
		char dst_ip[INET6_ADDRSTRLEN] = {0};
		inet_ntop(AF_INET6, &(ip6->ip6_src), src_ip, INET6_ADDRSTRLEN);
		inet_ntop(AF_INET6, &(ip6->ip6_dst), dst_ip, INET6_ADDRSTRLEN);

		u_int16_t source_port = ntohs(udp->uh_sport);
		u_int16_t destination_port = ntohs(udp->uh_dport);
		//printf("%s(%u) -> %s(%u)\n", src_ip, source_port, dst_ip, destination_port);

		u_char *message = (u_char *)(content + ETHER_HDR_LEN + 40 + 8);
		u_int32_t length = caplen - ETHER_HDR_LEN - 40 - 8;
		if (source_port == 53)
			dump_dns(length, message);
	}
}
*/
void dump_dns(u_int32_t length, const u_char *message) {
	struct dns_hdr *dns = (struct dns_hdr *)message;
	u_int16_t dns_id = ntohs(dns->dns_id);
	u_int16_t dns_flags = ntohs(dns->dns_flags);
	u_int16_t dns_question = ntohs(dns->dns_question);
	u_int16_t dns_answer = ntohs(dns->dns_answer);
	u_int16_t dns_authority = ntohs(dns->dns_authority);
	u_int16_t dns_additional = ntohs(dns->dns_additional);

	//request and response
	u_char *dns_start_ptr = (u_char *)message;
	u_char *current_ptr = (u_char *)(message + DNS_HDR_LEN);
	struct {
		char *prompt;
		int count;
		int response;
	} output[] = {
		{.prompt = "Questions", .count = dns_question, .response = 0},
		{.prompt = "Answers", .count = dns_answer, .response = 1},
		{.prompt = "Authority", .count = dns_authority, .response = 1},
		{"Additional", dns_additional, 1}
	};

	int unknown = 0;
	for(int i = 0 ; i < sizeof(output)/sizeof(output[0]) ; i++) {
		if(i == 1 && output[i].count){
			struct dns_entry *dns = dump_dns_data(dns_start_ptr, current_ptr, output[i].response);
			if(dns == NULL) break;
			char *qry_name = malloc(sizeof(char) * (strlen(dns->dns_name)+1));
			strcpy(qry_name, dns->dns_name);
			update_dns_table(dns, qry_name);
			current_ptr += dns->offset;
			free_dns_entry(dns);
			for(int j = 1 ; j < output[i].count ; j++) {
				struct dns_entry *dns = dump_dns_data(dns_start_ptr, current_ptr, output[i].response);
				if(dns == NULL) {
					unknown = 1;
					free_dns_entry(dns);
					free(qry_name);
					break;
				}
				update_dns_table(dns, qry_name);
				current_ptr += dns->offset;
				free_dns_entry(dns);
			}
			free(qry_name);
		}
		else{
			for(int j = 0 ; j < output[i].count ; j++) {
				struct dns_entry *dns = dump_dns_data(dns_start_ptr, current_ptr, output[i].response);
				if(dns == NULL) {
					unknown = 1;
					free_dns_entry(dns);
					break;
				}
				current_ptr += dns->offset;
				free_dns_entry(dns);
			}
		}
		if(unknown) break;
	}
}

int dump_domain_name(u_char *dns_start_ptr, u_char *current_ptr, char *buf, ssize_t buf_len) {
	u_char *ptr = current_ptr;
	int index = 0;
	int contain_name_pointer = 0;

	while(*ptr) {
		if(*ptr == 0xc0) {
			ptr = dns_start_ptr + *(ptr + 1); //next byte is the pointer from start
			contain_name_pointer = 1;
		}

		int length = *ptr;
		ptr++; //move to data
		memcpy(buf + index, ptr, length); //copy data
		ptr += length; //move length offset
		if(*ptr) {
			*(buf + index + length) = '.'; //just give the dot
			index += length + 1; //dot
		}
	}

	//count offset
	ptr = current_ptr;
	int offset = 0;
	while(*ptr) {
		offset++;
		if(*ptr == 0xc0) {
			offset++;
			break;
		}//end if meet 0xc0, read to break
		ptr++; //0xc0 won't be any printable char
	}
	return contain_name_pointer ? offset : offset + 1;
}

struct dns_entry *dump_dns_data(u_char *dns_start_ptr, u_char *current_ptr, int response) {
	struct dns_entry *dns = (struct dns_entry *)calloc(1, sizeof(struct dns_entry));
	if(!dns) {
		perror("calloc()");
		return NULL;
	}

	int offset = 0;
	dns->response = response;
	offset += dump_domain_name(dns_start_ptr, current_ptr, dns->dns_name, sizeof(dns->dns_name));
	dns->dns_type = ntohs(*(u_int16_t *)(current_ptr + offset)); //first two byte is type

	switch(dns->dns_type) {
		case DNS_TYPE_A:
		case DNS_TYPE_AAAA:
		case DNS_TYPE_CNAME:
		case DNS_TYPE_NS:
		case DNS_TYPE_ANY:  break;
		default:
			free_dns_entry(dns);
			return NULL;
	}
	offset += 2;

	dns->dns_class = ntohs(*(u_int16_t *)(current_ptr + offset));
	switch(dns->dns_class) {
		case DNS_CLASS_IN: break;
		default:
			free_dns_entry(dns);
			return NULL;
	}
	offset += 2;

	if(dns->response) {
		//ttl and data_len are universal field in the cast
		dns->dns_ttl = ntohl(*(int32_t *)(current_ptr + offset));
		offset += 4;
		dns->dns_data_length = ntohs(*(u_int16_t *)(current_ptr + offset));
		offset += 2;

		if(dns->dns_type == DNS_TYPE_A || dns->dns_type == DNS_TYPE_AAAA) {
			if(dns->dns_type == DNS_TYPE_A) {
				char addr[INET_ADDRSTRLEN] = {0};
				inet_ntop(AF_INET, current_ptr + offset, addr, INET_ADDRSTRLEN);
				offset += 4;
				memcpy(dns->u.type_a.addr, addr, strlen(addr) + 1);
			}
			else {
				char addr[INET6_ADDRSTRLEN] = {0};
				inet_ntop(AF_INET6, current_ptr + offset, addr, INET6_ADDRSTRLEN);
				offset += 16;
				memcpy(dns->u.type_a.addr, addr, strlen(addr) + 1);
			}
		}
		else if(dns->dns_type == DNS_TYPE_PTR || dns->dns_type == DNS_TYPE_CNAME) {
			offset += dump_domain_name(dns_start_ptr, current_ptr + offset, dns->u.type_ptr.name, sizeof(dns->u.type_ptr.name));
		}
		else if(dns->dns_type == DNS_TYPE_NS) {
			offset += dump_domain_name(dns_start_ptr, current_ptr + offset, dns->u.type_ns.name, sizeof(dns->u.type_ns.name));
		}
		else if(dns->dns_type == DNS_TYPE_SOA) {
			offset += dump_domain_name(dns_start_ptr, current_ptr + offset, dns->u.type_soa.name1, sizeof(dns->u.type_soa.name1));
			offset += dump_domain_name(dns_start_ptr, current_ptr + offset, dns->u.type_soa.name2, sizeof(dns->u.type_soa.name2));

			dns->u.type_soa.serial = ntohl(*(u_int32_t *)(current_ptr + offset));
			offset += 4;
			dns->u.type_soa.refresh = ntohl(*(u_int32_t *)(current_ptr + offset));
			offset += 4;
			dns->u.type_soa.retry = ntohl(*(u_int32_t *)(current_ptr + offset));
			offset += 4;
			dns->u.type_soa.expire = ntohl(*(u_int32_t *)(current_ptr + offset));
			offset += 4;
			dns->u.type_soa.minTTL = ntohl(*(u_int32_t *)(current_ptr + offset));
			offset += 4;
		}
		else{
			free_dns_entry(dns);
			return NULL;
		}
	}

	dns->offset = offset;
	return dns;
}

void update_dns_table(struct dns_entry *dns, char *qry_name) {
	struct {
		char name[DNS_MAX_LEN];
		char addr[INET_ADDRSTRLEN];
	} data;
	char buf[1024];
	if(dns->response) {
		if(dns->dns_type == DNS_TYPE_CNAME){
			// printf("qry_name: %s, cname: %s\n", qry_name, dns->u.type_cname.cname);
		}
		else if(dns->dns_type == DNS_TYPE_A || dns->dns_type == DNS_TYPE_AAAA){
			strncpy(data.name, qry_name, DNS_MAX_LEN);
			strncpy(data.addr, dns->u.type_a.addr, INET_ADDRSTRLEN);
			//printf("qry_name: %s, ip: %s\n", qry_name, dns->u.type_a.addr);
			snprintf(buf,1024,"qry_name %s ip %s\n", data.name, data.addr);
			write(STDOUT_FILENO, buf, 1024);
			// write(STDOUT_FILENO, &data, sizeof(data));
		}
	}
}

void free_dns_entry(struct dns_entry *dns) {
	if(dns) {
		memset(dns, 0, sizeof(struct dns_entry));
		free(dns);
	}
}
