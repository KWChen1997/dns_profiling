#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <string.h>
#include <time.h>
#include <linux/ip.h>
#include <linux/udp.h>

#ifndef __linux
#include <net/if.h>
#include <netinet/in.h>
#include <net/if_dl.h>
#include <net/ethernet.h>
#endif

#ifndef DNS_ANALYZE
#define DNS_ANALYZE
#define STR_BUF 16
#define DNS_DOMAIN_MAX_LEN (255 + 1)
#define DNS_MAX_LEN (512 + 1)
#define DNS_HDR_LEN (12)

#define DNS_TYPE_A 1
#define DNS_TYPE_NS 2
#define DNS_TYPE_CNAME 5
#define DNS_TYPE_SOA 6
#define DNS_TYPE_PTR 12
#define DNS_TYPE_AAAA 28
#define DNS_TYPE_ANY 255

#define DNS_CLASS_IN 1

#define MTU 1500

#define NIPQUAD(addr) \
	((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[3]


struct dns_hdr {
	u_int16_t dns_id;
	u_int16_t dns_flags;
	u_int16_t dns_question;
	u_int16_t dns_answer;
	u_int16_t dns_authority;
	u_int16_t dns_additional;
} __attribute__((packed));

struct dns_entry {
	int offset; /* dns entry data length */
	int response; /* is response */

	char dns_name[DNS_DOMAIN_MAX_LEN];
	u_int16_t dns_type;
	u_int16_t dns_class;
	int32_t dns_ttl;
	u_int16_t dns_data_length;
	union {
		struct {
			char addr[INET_ADDRSTRLEN];
		} type_a;
		struct {
			char addr[INET6_ADDRSTRLEN];
		} type_aaaa;
		struct {
			char name[DNS_DOMAIN_MAX_LEN];
		} type_ptr;
		struct {
			char cname[DNS_DOMAIN_MAX_LEN];
		} type_cname;
		struct {
			u_char txt_len;
			char txt[DNS_MAX_LEN];
		} type_txt;
		struct {
			u_int16_t preference;
			char name[DNS_DOMAIN_MAX_LEN];
		} type_mx;
		struct {
			char name[DNS_DOMAIN_MAX_LEN];
		} type_ns;
		struct {
			u_char version;
			u_char size;
			u_char horizontal;
			u_char vertial;
			u_int32_t latitude;
			u_int32_t longitude;
			u_int32_t altitude;
		} type_loc;
		struct {
			char service[DNS_DOMAIN_MAX_LEN];
			char proto[DNS_DOMAIN_MAX_LEN];
			char name[DNS_DOMAIN_MAX_LEN];
			u_int16_t priority;
			u_int16_t weight;
			u_int16_t port;
			char target[DNS_DOMAIN_MAX_LEN];
		} type_srv;
		struct {
			char name1[DNS_DOMAIN_MAX_LEN];
			char name2[DNS_DOMAIN_MAX_LEN];
			u_int32_t serial;
			u_int32_t refresh;
			u_int32_t retry;
			u_int32_t expire;
			u_int32_t minTTL;
		} type_soa;
	} u;
} __attribute__((packed));

int dump_packet(void *data, size_t data_len);
void dump_dns(u_int32_t length, const u_char *message, char *dst);
int dump_domain_name(u_char *dns_start_ptr, u_char *current_ptr, char *buf, ssize_t buf_len);
struct dns_entry *dump_dns_data(u_char *dns_start_ptr, u_char *current_ptr, int response);
void free_dns_entry(struct dns_entry *dns);
void update_dns_table(struct dns_entry *dns, char *qry_name, char *dst);
#endif
