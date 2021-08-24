#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/types.h>
#include <linux/netfilter.h>	
#include <libnetfilter_queue/libnetfilter_queue.h>

#include "filter.h"
#include "data_analysis.h"

#define NFQ_NUM 1

static u_int32_t print_pkt (struct nfq_data *tb)
{
	int id = 0;
	int ret;
	unsigned char *data;
	struct iphdr *iph;
	struct udphdr *udph;
	void *dns_payload;

	ret = nfq_get_payload(tb, &data);
	if (ret >= 0) {
		iph = (struct iphdr*)data;
		udph = (struct udphdr*)(data + iph->ihl * 4);
		if(ntohs(udph->source) != 53){
			return id;
		}
		dns_payload = (void*)data + iph->ihl * 4 + 8;
		dump_dns(ret - (dns_payload - (void*)iph), dns_payload);
	}

	return id;
}
	

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data)
{
//	u_int32_t id = print_pkt(nfa);
	u_int32_t id;
	
	int ret;
	unsigned char *payload;

        struct nfqnl_msg_packet_hdr *ph;
	ph = nfq_get_msg_packet_hdr(nfa);	
	id = ntohl(ph->packet_id);
	
	ret = nfq_get_payload(nfa,&payload);

	if(ret >= 0)
		print_pkt(nfa);
	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

	fprintf(stderr,"opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	fprintf(stderr,"unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	fprintf(stderr,"binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	fprintf(stderr,"binding this socket to queue '1'\n");
	qh = nfq_create_queue(h,  NFQ_NUM, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	fprintf(stderr,"setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	while ((rv = recv(fd, buf, sizeof(buf), 0)))
	{
		// printf("pkt received\n");
		nfq_handle_packet(h, buf, rv);
	}

	fprintf(stderr,"unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	fprintf(stderr,"unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	fprintf(stderr,"closing library handle\n");
	nfq_close(h);

	exit(0);
}
