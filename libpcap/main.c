#include "datalink_print.h"
#include "network_print.h"
#include "transport_print.h"
#include "util.h"

#include <pcap.h>
#include <locale.h>
#include <ncurses.h>
#include <signal.h>

#include <stdlib.h>
#include <string.h>

#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>
#include <arpa/inet.h>

#define PACKET_BUFSIZE 65536
#define SA struct sockaddr

static WINDOW *info_win;
static WINDOW *main_win;

//libpcap
pcap_t *phandle;

// initscr successfully called
bool ncurses_on;

// statistic counter
size_t packets_total;

void fail_exit(char const *msg);

void term_deinit(void);
void term_init(void);

void process_packet(unsigned char *args, const struct pcap_pkthdr *packet_hdr, 
                    const unsigned char *packet);
void print_statistic(WINDOW *win);

void print_packet(WINDOW *win, unsigned char const *buf, int size);
void sig_handle(int unused);

int main(int argc, char *argv[])
{
	if (argc < 2)
		fail_exit("sniffer devicename");

	struct sigaction act = {0};
	act.sa_handler = sig_handle;
	sigaction(SIGINT, &act, NULL);
	sigaction(SIGTERM, &act, NULL);

	term_init();

	char err_buf[PCAP_ERRBUF_SIZE];
	int packet_count_limit = 1;
	int timeout_limit = 1000; // milliseconds

	phandle = pcap_open_live(argv[1], BUFSIZ,
	                         packet_count_limit, timeout_limit,
	                         err_buf);
	if (!phandle)
		fail_exit("error pcap_open_live");

	print_statistic(info_win);
	doupdate();
	pcap_loop(phandle, -1, process_packet, NULL);

	term_deinit();

	exit(EXIT_SUCCESS);
}

void sig_handle(int unused)
{
	(void) unused;
	pcap_breakloop(phandle);
}

void fail_exit(char const *msg)
{
	//? !isendwin()
	if (ncurses_on)
		endwin();
	fprintf(stderr, "%s\n", msg);
	exit(EXIT_FAILURE);
}

void term_init(void)
{
	setlocale(LC_ALL, "");

	if (initscr() == NULL)
		fail_exit("Failed to initialize ncurses");

	ncurses_on = true;

	cbreak();
	noecho();
	curs_set(0);

	if (LINES >= 2) {
		info_win = newwin(LINES -1, COLS, LINES - 1, 0);
		main_win = newwin(LINES - 1, COLS, 0, 0);
	} else {
		fail_exit("Window is too small.");
	}

	if (info_win == NULL || main_win == NULL)
		fail_exit("Failed to ctreate windows.");

	keypad(main_win, TRUE);
	scrollok(main_win,TRUE);
}

void term_deinit(void)
{
	delwin(info_win);
	delwin(main_win);
	if (ncurses_on) {
		endwin();
		ncurses_on = false;
	}
}

void print_statistic(WINDOW *win)
{
	werase(win);
	wattron(win, A_REVERSE);
	wprintw(win, "Packets: %d", packets_total);
	wattroff(win, A_REVERSE);
	wnoutrefresh(win);
}

void process_packet(unsigned char *args, struct pcap_pkthdr const *packet_hdr,
                    unsigned char const *packet)
{
	(void)args; //unused
	print_packet(main_win, packet, packet_hdr->len);
	wnoutrefresh(main_win);
	packets_total++;
	print_statistic(info_win);
	doupdate();
}

void print_packet(WINDOW *win, unsigned char const* buf, int size)
{
	struct iphdr *iph = (struct iphdr*)(buf + sizeof(struct ethhdr));
	switch (iph->protocol) {
	case IPPROTO_ICMP:
		print_icmp_packet(win, buf, size);
		break;

	case IPPROTO_TCP:
		print_tcp_packet(win, buf, size);
		break;

	case IPPROTO_UDP:
		print_udp_packet(win, buf, size);
		break;

	default:
		print_unknown_packet(win, buf, size);
		break;
	}
	wprintw(win, "\n\n");
}

