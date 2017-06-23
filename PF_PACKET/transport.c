#include "transport.h"
#include "network.h"
#include "datalink.h"
#include <netinet/udp.h>
#include <netinet/tcp.h>

void *get_transport_hdr_ptr(unsigned char const *buf)
{
	return (unsigned char*)buf + get_ethhdr_len() + get_iphdr_len(buf);
}

int get_tcphdr_len(unsigned char const *buf)
{
	struct tcphdr *tcp = get_transport_hdr_ptr(buf);
	return tcp->doff * 4;
}

int check_tcphdr(unsigned char const *buf, int bufsize)
{
	if (buf && bufsize > 0
	    && (get_ethhdr_len() + get_iphdr_len(buf) + get_tcphdr_len(buf))
	    <= bufsize)
		return 0;
	return - 1;
}

int get_udphdr_len(void)
{
	return sizeof(struct udphdr);
}

int check_udphdr(unsigned char const *buf, int bufsize)
{
	if (buf && bufsize > 0
	    && (get_ethhdr_len() + get_iphdr_len(buf) + get_udphdr_len())
	    <= bufsize)
		return 0;
	return - 1;
}

