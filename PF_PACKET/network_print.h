#ifndef NETWORK_PRINT_H
#define NETWORK_PRINT_H

#include <ncurses.h>

int print_ip_hdr(WINDOW *win, unsigned char* buf, int bufsize);
int print_icmp_hdr(WINDOW *win, unsigned char* buf, int bufsize);
void print_icmp_packet(WINDOW *win, unsigned char* buf, int bufsize);

#endif
