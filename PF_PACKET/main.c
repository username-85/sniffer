#include "datalink_print.h"
#include "network_print.h"
#include "transport_print.h"
#include "util.h"

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

// initscr successfully called
bool ncurses_on;

// program is running
bool running = true;

// statistic counter
size_t packets_total;

void fail_exit(char const *msg);

void term_deinit(void);
void term_init(void);

void sniff(int rsock, unsigned char *buf, size_t bufsize);
void print_statistic(WINDOW *win);

void print_packet(WINDOW *win, unsigned char *buf, int size);
void sig_handle(int unused);

int main(void)
{
	struct sigaction act = {0};
	act.sa_handler = sig_handle;
	sigaction(SIGINT, &act, NULL);
	sigaction(SIGTERM, &act, NULL);

	term_init();

	unsigned char *buf = (unsigned char *)malloc(PACKET_BUFSIZE);
	if (!buf)
		fail_exit("Error. malloc");

	int sock_raw = socket( PF_PACKET, SOCK_RAW, htons(ETH_P_ALL)) ;
	if (sock_raw < 0)
		fail_exit("Error. Could not create raw socket.");

	print_statistic(info_win);
	doupdate();

	while (running) {
		sniff(sock_raw, buf, PACKET_BUFSIZE);
		print_statistic(info_win);
		doupdate();
	}

	term_deinit();
	free(buf);

	exit(EXIT_SUCCESS);
}

void sig_handle(int unused)
{
	(void) unused;
	running = false;
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

void sniff(int rsock, unsigned char *buf, size_t bufsize)
{
	struct sockaddr_storage saddr;
	socklen_t saddr_size = sizeof(saddr);

	int data_size = recvfrom(rsock, buf, bufsize,
	                         0, (SA *)&saddr, &saddr_size);
	if (data_size < 0)
		wprintw(main_win, "\nrecvfrom error, failed to get packet\n");

	print_packet(main_win, buf, data_size);
	wnoutrefresh(main_win);
	packets_total++;
}

void print_packet(WINDOW *win, unsigned char* buf, int size)
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

