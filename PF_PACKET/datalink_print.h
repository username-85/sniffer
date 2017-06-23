#ifndef DATALINK_PRINT_H
#define DATALINK_PRINT_H

#include <ncurses.h>
#include <net/ethernet.h>

int print_eth_hdr(WINDOW *win, unsigned char *buf, int bufsize);

#endif
