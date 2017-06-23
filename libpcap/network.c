#include "network.h"
#include "datalink.h"

#include <netinet/ip_icmp.h>

int get_iphdr_len(unsigned char const *buf)
{
	struct iphdr *ip = get_iphdr_ptr(buf);
	return (ip->ihl * 4);
}

void *get_iphdr_ptr(unsigned char const *buf)
{
	return (unsigned char*)buf + get_ethhdr_len();
}

int check_iphdr(unsigned char const *buf, int bufsize)
{
	if (buf && bufsize > 0
	    && (get_ethhdr_len() + get_iphdr_len(buf))
	    <= bufsize)
		return 0;
	return - 1;
}

void *get_icmp_ptr(unsigned char const *buf)
{
	return (unsigned char*)buf + get_ethhdr_len() + get_iphdr_len(buf);
}

int get_icmphdr_len(void)
{
	return sizeof(struct icmphdr);
}

int check_icmphdr(unsigned char const *buf, int bufsize)
{
	if (buf && bufsize > 0
	    && (get_ethhdr_len() + get_iphdr_len(buf) + get_icmphdr_len())
	    <= bufsize)
		return 0;
	return - 1;
}
