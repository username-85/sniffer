#include "network_print.h"
#include "network.h"
#include "datalink_print.h"
#include "datalink.h"
#include "util.h"

#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <string.h>

int print_ip_hdr(WINDOW *win, unsigned char* buf, int bufsize)
{
	if (check_iphdr(buf, bufsize) !=0) {
		wprintw(win, "IP ERR\t");
		return -1;
	}

	struct iphdr *ip = get_iphdr_ptr(buf);

	struct sockaddr_in source, dest;
	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = ip->saddr;
	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = ip->daddr;

	wprintw(win, "IP\t");
	wprintw(win, "ver %d", (unsigned int)ip->version);
	wprintw(win, "   len %d", ntohs(ip->tot_len));
	wprintw(win, "   ttl %d", (unsigned int)ip->ttl);
	wprintw(win, "   prot %d", (unsigned int)ip->protocol);
	wprintw(win, "   checksum %d", ntohs(ip->check));
	wprintw(win, "   srcIP %s",  inet_ntoa(source.sin_addr));
	wprintw(win, "   destIP %s", inet_ntoa(dest.sin_addr));

	return 0;
}

int print_icmp_hdr(WINDOW *win, unsigned char* buf, int bufsize)
{
	if (check_icmphdr(buf, bufsize) !=0) {
		wprintw(win, "ICMP ERR\t");
		return -1;
	}

	struct icmphdr *icmp = get_icmp_ptr(buf);

	wprintw(win, "ICMP\t");
	wprintw(win, "type %d", (unsigned int)(icmp->type));
	wprintw(win, "   code %d",(unsigned int)(icmp->code));
	wprintw(win, "   checksum %d", ntohs(icmp->checksum));

	return 0;
}

void print_icmp_packet(WINDOW *win, unsigned char* buf, int bufsize)
{
	int hdrs_len = get_ethhdr_len() + get_iphdr_len(buf) +
	               get_icmphdr_len();
	int pdata_size = bufsize - hdrs_len;
	unsigned char *pdata = buf + hdrs_len;

	print_eth_hdr(win, buf, bufsize);
	wprintw(win, "\n");
	print_ip_hdr(win, buf, bufsize);
	wprintw(win, "\n");
	print_icmp_hdr(win, buf, bufsize);
	wprintw(win, "\n");
	print_data_ascii(win, pdata, pdata_size);
	wprintw(win, "\n");
	print_data_hex(win, pdata, pdata_size);
}

