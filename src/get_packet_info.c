#include <netinet/tcp.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <arpa/inet.h>
#include <stdlib.h>

void get_packet_info (unsigned char *payload, int *version, int *ip_address, int *sport, int *dport, int *synflag) {
	int ip_header_length, header_size, vsn;

        vsn = payload[0] & 0xF0;
        vsn >>= 4;

	*version = vsn;
	if (vsn != 4) return;

	ip_header_length = payload[0] & 0x0F;
	header_size = ip_header_length * 4;

	*ip_address = (payload[12] << 24) | (payload[13] << 16) | (payload[14] << 8) | payload[15];

	*sport = (payload[header_size] << 8) | payload[header_size + 1];

	*dport = (payload[header_size + 2] << 8) | payload[header_size + 3];

	*synflag = (payload[header_size + 13] & 0x3F) & TH_SYN;
}

int get_packet_id (struct nfq_data *nfa, int *id) {
	struct nfqnl_msg_packet_hdr *hdr = nfq_get_msg_packet_hdr(nfa);
	if (hdr != NULL) {
		*id = ntohl(hdr->packet_id);
		return 1;
	}
	return 0;
}
