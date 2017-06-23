#ifndef TRANSPORT_PRINT_H
#define TRANSPORT_PRINT_H

#include <ncurses.h>

int print_tcp_hdr(WINDOW *win, unsigned char *buf, int bufsize);
int print_tcp_packet(WINDOW *win, unsigned char *buf, int bufsize);

int print_udp_hdr(WINDOW *win, unsigned char* buf, int bufsize);
int print_udp_packet(WINDOW *win, unsigned char *buf, int bufsize);

#endif

