#include "transport_print.h"
#include "transport.h"
#include "network.h"
#include "network_print.h"
#include "datalink.h"
#include "datalink_print.h"
#include "util.h"


#include <arpa/inet.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>

int print_tcp_hdr(WINDOW *win, unsigned char *buf, int bufsize)
{
	if (check_tcphdr(buf, bufsize) !=0) {
		wprintw(win, "TCP ERR\t");
		return -1;
	}

	struct tcphdr *tcp = get_transport_hdr_ptr(buf);

	wprintw(win, "TCP\t");
	wprintw(win, "src port %u", ntohs(tcp->source));
	wprintw(win, "   dest port %u",ntohs(tcp->dest));
	wprintw(win, "   seq# %u",ntohl(tcp->seq));
	wprintw(win, "   ack# %u",ntohl(tcp->ack_seq));
	wprintw(win, "   win size %d", ntohs(tcp->window));
	wprintw(win, "   checksum %d", ntohs(tcp->check));

	wprintw(win, "   flags(");
	if (tcp->urg)
		wprintw(win, " urg");
	if (tcp->ack)
		wprintw(win, " ack");
	if (tcp->psh)
		wprintw(win, " psh");
	if (tcp->rst)
		wprintw(win, " rst");
	if (tcp->syn)
		wprintw(win, " syn");
	if (tcp->fin)
		wprintw(win, " fin");
	wprintw(win, ")");

	return 0;
}

int print_tcp_packet(WINDOW *win, unsigned char *buf, int bufsize)
{
	int hdrs_len = get_ethhdr_len() + get_iphdr_len(buf)
	               + get_tcphdr_len(buf);
	int pdata_size = bufsize - hdrs_len;
	unsigned char *pdata = buf + hdrs_len;

	print_eth_hdr(win, buf, bufsize);
	wprintw(win, "\n");
	print_ip_hdr(win, buf, bufsize);
	wprintw(win, "\n");
	print_tcp_hdr(win, buf, bufsize);
	wprintw(win, "\n");
	print_data_ascii(win, pdata, pdata_size);
	wprintw(win, "\n");
	print_data_hex(win, pdata, pdata_size);

	return 0;
}


int print_udp_hdr(WINDOW *win, unsigned char* buf, int bufsize)
{
	if (check_udphdr(buf, bufsize) !=0) {
		wprintw(win, "UDP ERR\t");
		return -1;
	}

	struct udphdr *udp = get_transport_hdr_ptr(buf);
	wprintw(win, "UDP\t");
	wprintw(win, "src port %d", ntohs(udp->source));
	wprintw(win, "   dest port %d", ntohs(udp->dest));
	wprintw(win, "   length %d", ntohs(udp->len));
	wprintw(win, "   checksum %d", ntohs(udp->check));

	return 0;
}

int print_udp_packet(WINDOW *win, unsigned char *buf, int bufsize)
{
	int hdrs_len = get_ethhdr_len() + get_iphdr_len(buf) + get_udphdr_len();
	int pdata_size = bufsize - hdrs_len;
	unsigned char *pdata = buf + hdrs_len;

	print_eth_hdr(win, buf, bufsize);
	wprintw(win, "\n");
	print_ip_hdr(win, buf, bufsize);
	wprintw(win, "\n");
	print_udp_hdr(win, buf, bufsize);
	wprintw(win, "\n");
	print_data_ascii(win, pdata, pdata_size);
	wprintw(win, "\n");
	print_data_hex(win, pdata, pdata_size);

	return 0;
}

