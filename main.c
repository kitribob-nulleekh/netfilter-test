#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <time.h>
#include <string.h>

typedef _Bool bool;
#define false	(_Bool)0;
#define true	(_Bool)1;

bool flag = false;

char* blockedHost;

void usage() {
	printf("syntax : netfilter-test <host> <durationTime>\n");
	printf("sample : netfilter-test test.gilgil.net 333\n");
}

bool checkHost(unsigned char* _data) {
	struct ip* ipHeader;
	struct tcphdr* tcpHeader;

	uint32_t ipLen, tcpOffset, httpSize, payloadLen;

	char* payload;

	ipHeader = (struct ip*)(_data);
	ipLen = (ipHeader->ip_hl)*4;
	if (ipHeader->ip_p != IPPROTO_TCP)
		printf("===>Not TCP");
	else {
		if (20 > ipLen) 
			printf("===>Invalid IP Header");
		else {
			tcpHeader = (struct tcphdr*)(_data + ipLen);
			tcpOffset = (tcpHeader->th_off)*4;
			if (20 > tcpOffset)
				printf("===>Invalid TCP Header");
			else {
				payloadLen = ntohs(ipHeader->ip_len)-ipLen-tcpOffset;
				if (0 >= payloadLen)
					printf("===>No Payload");
				else {
					payload = (char*)(_data + ipLen + tcpOffset);
					
					payload[payloadLen-1] = 0;
					
					const char* pathStart = strstr(payload, "Host: ");
					if (NULL == pathStart)
						printf("===>No Host");
					else {
						pathStart += 6;
						const char* queryStart = strstr(pathStart, "User-Agent: ") - 1;
						if (NULL == queryStart)
							printf("===>No User-Agent");
						else {
							char path[queryStart - pathStart];
			
							printf("===>%s", path);

							strncpy(path, pathStart, queryStart-pathStart);
							path[queryStart - pathStart - 1] = 0;
				
							if (0 == strcmp(path, blockedHost))
								return true;
						}
					}
				}
			}
		}
	}
	return false;
}


/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi;
	int ret;
	unsigned char *data;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
		printf("hw_protocol=0x%04x hook=%u id=%u\n",
			ntohs(ph->hw_protocol), ph->hook, id);
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

		printf("hw_src_addr=");
		for (i = 0; i < hlen-1; i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x\n", hwph->hw_addr[hlen-1]);
	}

	mark = nfq_get_nfmark(tb);
	if (mark)
		printf("mark=%u\n", mark);

	ifi = nfq_get_indev(tb);
	if (ifi)
		printf("indev=%u\n", ifi);

	ifi = nfq_get_outdev(tb);
	if (ifi)
		printf("outdev=%u\n", ifi);
	ifi = nfq_get_physindev(tb);
	if (ifi)
		printf("physindev=%u\n", ifi);

	ifi = nfq_get_physoutdev(tb);
	if (ifi)
		printf("physoutdev=%u\n", ifi);

	ret = nfq_get_payload(tb, &data);
	if (ret >= 0) {
		printf("payload_len=%d\n", ret);
		flag = checkHost(data);
	}

	fputc('\n', stdout);

	return id;
}


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	u_int32_t id = print_pkt(nfa);
	printf("entering callback\n");
	if (flag) {
		printf("=========>DROP\n\n\n");
		return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
	} else {
		printf("=========>ACCEPT\n\n\n");
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
	}
}

int main(int argc, char **argv)
{
	if (3 != argc) {
		usage();
		return -1;
	}

	blockedHost = (char*)(argv[1]);

	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	time_t durationTime = atoi(argv[2]);
	char buf[4096] __attribute__ ((aligned));

	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	time_t startTime = time(NULL);

	for (;;) {
		if (time(NULL) > startTime + durationTime) {
			printf("\n\n\n=== END TASK ===\n\n\n");
			break;
		} else if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		} else if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}

