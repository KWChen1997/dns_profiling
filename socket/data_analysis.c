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

int dump_packet(void *data, size_t data_len){
	struct ether_header *ethdr;
	ethdr = data;
	struct iphdr *iph = (void*)data + sizeof(struct ether_header);
	struct udphdr *uhdr = (void*)data + sizeof(struct ether_header) + ((iph->ihl & 0x0f) << 2);

	// Debugging message
	puts("ether");
	fprintf(stderr,"dest: %02x:%02x:%02x:%02x:%02x:%02x\n", ethdr->ether_dhost[0], ethdr->ether_dhost[1], ethdr->ether_dhost[2], ethdr->ether_dhost[3], ethdr->ether_dhost[4], ethdr->ether_dhost[5]);
	fprintf(stderr,"src: %02x:%02x:%02x:%02x:%02x:%02x\n", ethdr->ether_shost[0], ethdr->ether_shost[1], ethdr->ether_shost[2], ethdr->ether_shost[3], ethdr->ether_shost[4], ethdr->ether_shost[5]);
	fprintf(stderr,"prot: 0x%04x\n", ntohs(ethdr->ether_type));
	puts("iphdr");
	fprintf(stderr,"dest: %u.%u.%u.%u\n", NIPQUAD(iph->daddr));
	fprintf(stderr,"src: %u.%u.%u.%u\n", NIPQUAD(iph->saddr));

	puts("udphdr");
	fprintf(stderr,"dest: %u\n", ntohs(uhdr->dest));
	fprintf(stderr,"src: %u\n", ntohs(uhdr->source));

	puts("dns");

	// dump dns data
	char dst[16];
	snprintf(dst,16,"%u.%u.%u.%u", NIPQUAD(iph->daddr));
	dump_dns(uhdr->len-8,(void*)uhdr + 8,dst);
	return 0;
}

void dump_dns(u_int32_t length, const u_char *message, char *dst) {
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
			update_dns_table(dns, qry_name,dst);
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
				update_dns_table(dns, qry_name,dst);
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

void update_dns_table(struct dns_entry *dns, char *qry_name, char *dst) {
	struct {
		char dst[INET_ADDRSTRLEN];
		char name[DNS_DOMAIN_MAX_LEN];
		char addr[INET_ADDRSTRLEN];
	} data;
	char buf[1024];
	if(dns->response) {
		if(dns->dns_type == DNS_TYPE_CNAME){
			// printf("qry_name: %s, cname: %s\n", qry_name, dns->u.type_cname.cname);
		}
		else if(dns->dns_type == DNS_TYPE_A){
			strncpy(data.name, qry_name, DNS_DOMAIN_MAX_LEN);
			strncpy(data.addr, dns->u.type_a.addr, INET_ADDRSTRLEN);
			strncpy(data.dst, dst, INET_ADDRSTRLEN);
			//debugging message
			snprintf(buf,1024,"dst %s qry_name %s ip %s\n",data.dst, data.name, data.addr);
			fprintf(stderr,"%s", buf);
			//sending data to anom_detector
			write(STDOUT_FILENO, &data, sizeof(data));
		}
	}
}

void free_dns_entry(struct dns_entry *dns) {
	if(dns) {
		memset(dns, 0, sizeof(struct dns_entry));
		free(dns);
	}
}
