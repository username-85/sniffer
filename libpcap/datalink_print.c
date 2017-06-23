#include "datalink_print.h"
#include "datalink.h"
#include <string.h>

int print_eth_hdr(WINDOW *win, unsigned char const *buf, int bufsize)
{
	if (check_ethhdr(buf, bufsize) != 0) {
		wprintw(win, "ETH ERR\t");
		return -1;
	}

	struct ethhdr *eth = (struct ethhdr *)buf;

	wprintw(win, "ETH\t");
	wprintw(win, "src %.2X-%.2X-%.2X-%.2X-%.2X-%.2X",
	        eth->h_source[0], eth->h_source[1], eth->h_source[2],
	        eth->h_source[3], eth->h_source[4], eth->h_source[5]);

	wprintw(win, "  dest %.2X-%.2X-%.2X-%.2X-%.2X-%.2X",
	        eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
	        eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
	wprintw(win, "  protocol: %d", eth->h_proto);

	return 0;
}

